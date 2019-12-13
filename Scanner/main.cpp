#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>
#include <algorithm>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ConnSocket.hpp"
#include "IPSpaceSweeper.hpp"
#include "DataStore.hpp"


SSL_CTX_ptr g_ssl_ctx(nullptr, SSL_CTX_free);;


static bool g_keep_running = true;


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
      const size_t concurrency = 5000;
      std::vector<ConnSocket> socks(concurrency);
      std::vector<pollfd>  fdas(concurrency);
      IPSpaceSweeper ip_range;

      //ip_range.add_range("200.147.118.0", 24);
      ip_range.add_range("200.0.0.0", 6);

      DataStore datastore;

      printf("Starting scan...\n");

      const auto stat_interval = 5000;
      const auto start = GetTickCount64();
      auto last_stat = start;

      size_t returnedData = 0;
      while (g_keep_running)
      {
         bool is_there_active_conn = false;
         for (size_t i = 0; i < socks.size(); ++i)
         {
            if (socks[i].is_connected())
            {
               is_there_active_conn = true;
            }
            else if (!ip_range.has_range_finished())
            {
               const auto ip = ip_range.get_ip();
               //printf("Testing %d.%d.%d.%d\n", ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
               if (!socks[i].connect(ip, 443))
               {
                  printf("Error connecting socket %zd to ip 0x%08lX\n", i, ip);
                  const auto ret = socks[i].get_result();
                  if (!datastore.insert(ret.ip, ret.port, ret.result, ret.data, ret.data_len))
                  {
                     printf("Error storing raw response\n");
                  }
               }
               else
               {
                  is_there_active_conn = true;
                  fdas[i] = socks[i].get_pollfd();
               }
            }
         }

         if (!is_there_active_conn)
         {
            printf("Finished scanning\n");
            break;
         }

         socks.erase(std::remove_if(socks.begin(), socks.end(), [](const auto& it) {return !it.is_connected(); }), socks.end());
         fdas.resize(socks.size());
         for (size_t i = 0; i < socks.size(); ++i)
         {
            fdas[i] = socks[i].get_pollfd();
         }

         int ret = poll(fdas.data(), static_cast<unsigned long>(fdas.size()), 100);
         if (ret < 0)
         {
            printf("WSAPoll error - Error=%d\n", WSAGetLastError());
            break;
         }
         
         if (!datastore.begin())
         {
            printf("Error starting data store transaction\n");
         }

         for (size_t i = 0; i < socks.size(); ++i)
         {
            if (socks[i].process_poll(fdas[i]))
            {
               const auto ret = socks[i].get_result();
               if (!datastore.insert(ret.ip, ret.port, ret.result, ret.data, ret.data_len))
               {
                  printf("Error storing raw response\n");
               }

               if (ret.result == ConnSocket::Result_e::TLSHandshakeCompleted)
               {
                  ++returnedData;
               }
               socks[i].disconnect();
            }
         }

         if (!datastore.commit())
         {
            printf("Error commiting data store transaction\n");
         }

         const auto now = GetTickCount64();
         if ((now - last_stat) >= stat_interval)
         {
            const auto [current, max_count] = ip_range.get_stats();
            const auto percentage = (100.0 * current) / max_count;
            const auto data_percentage = (100.0 * returnedData) / current;
            const unsigned long long elapsed = (now - start) / 1000;
            const unsigned long long remaining = static_cast<unsigned long long>(((elapsed * 100) / percentage) - elapsed);

            const auto elapsed_sec = elapsed % 60;
            const auto elapsed_min = (elapsed / 60) % 60;
            const auto elapsed_hou = (elapsed / 3600);

            const auto remaining_sec = remaining % 60;
            const auto remaining_min = (remaining / 60) % 60;
            const auto remaining_hou = (remaining / 3600);

            printf(  "\n******************** PROGRESS ********************\n"
                     "  Sweeped %lu of %lu addresses - %5.2f%%\n"
                     "  %zd IPs returned data - %5.2f%%\n"
                     "  Elapsed:   %4lldh %02lldmin %02llds\n"
                     "  Remaining: %4lldh %02lldmin %02llds\n",
                     current, max_count, percentage,
                     returnedData, data_percentage,
                     elapsed_hou, elapsed_min, elapsed_sec,
                     remaining_hou, remaining_min, remaining_sec);

            last_stat = now;
         }
      }

      printf("Exited main loop\n");

      const auto [current, max_count] = ip_range.get_stats();
      const auto percentage = (100.0 * current) / max_count;
      const auto data_percentage = (100.0 * returnedData) / current;
      const unsigned long long elapsed = (GetTickCount64() - start) / 1000;

      const auto elapsed_sec = elapsed % 60;
      const auto elapsed_min = (elapsed / 60) % 60;
      const auto elapsed_hou = (elapsed / 3600);

      printf("\n******************** FINISHED ********************\n");
      printf("  Sweeped %lu of %lu addresses - %5.2f%%\n", current, max_count, percentage);
      printf("  %zd IPs returned data - %5.2f%%\n", returnedData, data_percentage);
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