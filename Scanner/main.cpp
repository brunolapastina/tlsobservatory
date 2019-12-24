#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>
#include <atomic>
#include <algorithm>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ConnSocket.hpp"
#include "IPSpaceSweeper.hpp"
#include "DataStore.hpp"

SSL_CTX_ptr g_ssl_ctx(nullptr, SSL_CTX_free);;


static bool g_keep_running = true;
static std::atomic_size_t g_overall_probed = 0;
static std::atomic_size_t g_overall_returnedData = 0;
static std::atomic_size_t g_overall_storedResults = 0;


static constexpr int stat_interval = 5000;
static constexpr size_t max_sockets = 60000;


#ifdef _WIN32
   static BOOL consoleHandler(DWORD signal)
   {
      if (signal == CTRL_C_EVENT)
      {
         printf("Exiting...\n");
         g_keep_running = false;
      }
      return true;
   }
#else
   
#endif


void exec_thread(DataStore& datastore, IPSpaceSweeper ip_range, const size_t sockets_by_thread)
{
   std::vector<ConnSocket> socks(sockets_by_thread);
   std::vector<pollfd>  fdas(sockets_by_thread);

   printf("Starting scan...\n");

   while (g_keep_running)
   {
      bool is_there_active_conn = false;
      bool need_remove = false;
      size_t probed = 0;
      size_t storedResults = 0;
      for (size_t i = 0; i < socks.size(); ++i)
      {
         if (socks[i].is_connected())
         {
            is_there_active_conn = true;
         }
         else if (!ip_range.has_range_finished())
         {
            const auto ip = ip_range.get_ip();
            ++probed;
            //printf("Testing %d.%d.%d.%d\n", ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
            if (!socks[i].connect(ip, 443))
            {
               printf("Error connecting socket %zd to ip 0x%08lX\n", i, ip);
               const auto ret = socks[i].get_result();
               if (ret.result != ConnSocket::Result_e::TCPHandshakeTimeout)
               {
                  if (!datastore.insert(ret.ip, ret.port, ret.result, ret.data, ret.data_len))
                  {
                     printf("Error storing raw response\n");
                  }
                  ++storedResults;
               }
               need_remove = true;
            }
            else
            {
               is_there_active_conn = true;
               fdas[i] = socks[i].get_pollfd();
            }
         }
         else
         {
            need_remove = true;
         }
      }

      g_overall_probed += probed;

      if (!is_there_active_conn)
      {
         printf("Finished scanning\n");
         break;
      }

      if (need_remove)
      {
         socks.erase(std::remove_if(socks.begin(), socks.end(), [](const auto& it) {return !it.is_connected(); }), socks.end());
         fdas.resize(socks.size());
         for (size_t i = 0; i < socks.size(); ++i)
         {
            fdas[i] = socks[i].get_pollfd();
         }
      }

      int ret = poll(fdas.data(), static_cast<unsigned long>(fdas.size()), 500);
      if (ret < 0)
      {
         printf("WSAPoll error - Error=%d\n", WSAGetLastError());
         break;
      }

      size_t returnedData = 0;
      for (size_t i = 0; i < socks.size(); ++i)
      {
         if (socks[i].process_poll(fdas[i]))
         {
            const auto ret = socks[i].get_result();
            if (ret.result != ConnSocket::Result_e::TCPHandshakeTimeout)
            {
               if (!datastore.insert(ret.ip, ret.port, ret.result, ret.data, ret.data_len))
               {
                  printf("Error storing raw response\n");
               }

               if (ret.result == ConnSocket::Result_e::TLSHandshakeCompleted)
               {
                  ++returnedData;
               }
               ++storedResults;
            }
            socks[i].disconnect();
         }
      }

      g_overall_returnedData += returnedData;
      g_overall_storedResults += storedResults;
   }
}


int main()
{
   #ifdef _WIN32
      SetConsoleCtrlHandler(consoleHandler, TRUE);

      WSADATA wsaData = { 0 };
      int iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
      if (iRet != 0)
      {
         wprintf(L"WSAStartup failed: %d\n", iRet);
         return 1;
      }
   #endif

   SSL_library_init();
   SSLeay_add_ssl_algorithms();
   SSL_load_error_strings();

   sqlite3_initialize();

   g_ssl_ctx.reset(SSL_CTX_new(SSLv23_client_method()));

   try
   {
      IPSpaceSweeper ip_range;

      //ip_range.add_range("200.147.118.0", 24);
      ip_range.add_range("192.0.0.0", 2);

      DataStore datastore;

      std::vector<std::thread> threads;
      const unsigned int num_of_threads =  2 * std::thread::hardware_concurrency();
      const size_t concurrency = max_sockets / num_of_threads;

      const auto start = GetTickCount64();

      printf("Starting %u threads with max_sockets = %zd\n", num_of_threads, max_sockets);

      threads.reserve(num_of_threads);
      for (unsigned int i = 0; i < num_of_threads; ++i)
      {
         threads.emplace_back(exec_thread, std::ref(datastore), ip_range.get_slice(num_of_threads, i), concurrency);
      }

      auto last_stat = GetTickCount64();

      while (g_keep_running)
      {
         Sleep(100);
         const auto now = GetTickCount64();
         if ((now - last_stat) >= stat_interval)
         {
            const auto probed = g_overall_probed.load();
            const auto returnedData = g_overall_returnedData.load();
            const auto storedResults = g_overall_storedResults.load();
            const auto [dummy, max_count] = ip_range.get_stats();
            const auto percentage = (100.0 * probed) / max_count;
            const auto data_percentage = (100.0 * returnedData) / probed;
            const auto results_percentage = (100.0 * storedResults) / probed;
            const unsigned long long elapsed = (now - start) / 1000;
            const unsigned long long remaining = static_cast<unsigned long long>(((elapsed * 100) / percentage) - elapsed);

            const auto elapsed_sec = elapsed % 60;
            const auto elapsed_min = (elapsed / 60) % 60;
            const auto elapsed_hou = (elapsed / 3600);

            const auto remaining_sec = remaining % 60;
            const auto remaining_min = (remaining / 60) % 60;
            const auto remaining_hou = (remaining / 3600);

            printf("\n******************** PROGRESS ********************\n"
               "  Sweeped %zd of %lu addresses - %5.2f%%\n"
               "  %zd IPs returned data - %5.2f%%\n"
               "  %zd IPs stored some result - %5.2f%%\n"
               "  Elapsed:   %4lldh %02lldmin %02llds\n"
               "  Remaining: %4lldh %02lldmin %02llds\n",
               probed, max_count, percentage,
               returnedData, data_percentage,
               storedResults, results_percentage,
               elapsed_hou, elapsed_min, elapsed_sec,
               remaining_hou, remaining_min, remaining_sec);

            if (probed >= max_count)
            {  // Finished
               break;
            }

            last_stat = now;
         }
      }

      for (auto& it : threads)
      {
         if (it.joinable())
         {
            it.join();
         }
      }

      datastore.commit_transaction();

      const auto probed = g_overall_probed.load();
      const auto returnedData = g_overall_returnedData.load();
      const auto storedResults = g_overall_storedResults.load();
      const auto [dummy, max_count] = ip_range.get_stats();
      const auto percentage = (100.0 * probed) / max_count;
      const auto data_percentage = (100.0 * returnedData) / probed;
      const auto results_percentage = (100.0 * storedResults) / probed;
      const unsigned long long elapsed = (GetTickCount64() - start) / 1000;

      const auto elapsed_sec = elapsed % 60;
      const auto elapsed_min = (elapsed / 60) % 60;
      const auto elapsed_hou = (elapsed / 3600);

      printf("\n******************** FINISHED ********************\n");
      printf("  Sweeped %zd of %lu addresses - %5.2f%%\n", probed, max_count, percentage);
      printf("  %zd IPs returned data - %5.2f%%\n", returnedData, data_percentage);
      printf("  %zd IPs stored some result - %5.2f%%\n", storedResults, results_percentage);
      printf("  Elapsed: %lldh %02lldmin %02llds\n", elapsed_hou, elapsed_min, elapsed_sec );
      printf("\n**************************************************\n");
   }
   catch (std::exception & e)
   {
      printf("EXCEPTION: %s\n", e.what());
   }

   sqlite3_shutdown();

   #ifdef _WIN32
      WSACleanup();
      system("pause");
   #endif

   return 0;
}