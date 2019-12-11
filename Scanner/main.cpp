#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>
#include <algorithm>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ConnSocket.hpp"
#include "IPSpaceSweeper.hpp"
#include "DataStore.hpp"

SSL_CTX_ptr g_ssl_ctx(nullptr, SSL_CTX_free);;

static bool g_keep_running = true;

BOOL consoleHandler(DWORD signal) {

   if (signal == CTRL_C_EVENT)
   {
      printf("Exiting...\n");
      g_keep_running = false;
   }
   return true;
}

int main()
{
   SetConsoleCtrlHandler(consoleHandler, TRUE);

   SSL_library_init();
   SSLeay_add_ssl_algorithms();
   SSL_load_error_strings();

   g_ssl_ctx.reset(SSL_CTX_new(SSLv23_client_method()));

   WSADATA wsaData = { 0 };
   int iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
   if (iRet != 0)
   {
      wprintf(L"WSAStartup failed: %d\n", iRet);
      return 1;
   }

   try
   {
      const size_t concurrency = 10000;
      std::vector<ConnSocket> socks(concurrency);
      std::vector<WSAPOLLFD>  fdas(concurrency);
      IPSpaceSweeper ip_range;

      //ip_range.add_range("200.147.118.0", 24);
      ip_range.add_range("200.0.0.0", 8);

      DataStore datastore;

      printf("Starting scan...\n");

      const auto stat_interval = std::chrono::seconds(5);
      const auto start = std::chrono::system_clock::now();
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
                  printf("Error connecting socket %zd\n", i);
                  return -1;
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
         for (int i = 0; i < socks.size(); ++i)
         {
            fdas[i] = socks[i].get_pollfd();
         }

         int ret = WSAPoll(fdas.data(), static_cast<ULONG>(fdas.size()), 100);
         if (ret < 0)
         {
            printf("WSAPoll error - Error=%d\n", WSAGetLastError());
            break;
         }
         else
         {
            if (!datastore.begin())
            {
               printf("Error starting data store transaction\n");
            }

            for (int i = 0; i < socks.size(); ++i)
            {
               if (socks[i].process_poll(fdas[i]))
               {
                  auto ret = socks[i].get_result();
                  if (ret.data_len > 0)
                  {
                     //printf("IP.%08X:%d  ->  Data(%zd)\n", ret.ip, ret.port, ret.data_len);
                     if (!datastore.insert(ret.ip, ret.port, ret.result, ret.data, ret.data_len))
                     {
                        printf("Error storing raw response\n");
                     }
                     ++returnedData;
                  }
                  socks[i].disconnect();
               }
            }

            if (!datastore.commit())
            {
               printf("Error commiting data store transaction\n");
            }
         }

         if ((std::chrono::system_clock::now() - last_stat) >= stat_interval)
         {
            const auto [current, max_count] = ip_range.get_stats();
            const auto percentage = (100.0 * current) / max_count;
            const auto data_percentage = (100.0 * returnedData) / current;
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - start);
            const auto remaining = ((elapsed.count() * 100.0) / percentage) - elapsed.count();

            printf(  "\n******************** PROGRESS ********************\n"
                     "  Sweeped %u of %u addresses - %5.2f%%\n"
                     "  %zd IPs returned data - %5.2f%%\n"
                     "  Elapsed %lld seconds\n"
                     "  Estimated remaining time: %.0f seconds\n",
                     current, max_count, percentage,
                     returnedData, data_percentage,
                     elapsed.count(),
                     remaining );

            last_stat = std::chrono::system_clock::now();
         }
      }

      printf("Exited main loop\n");

      const auto [current, max_count] = ip_range.get_stats();
      const auto percentage = (100.0 * current) / max_count;
      const auto data_percentage = (100.0 * returnedData) / current;
      const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - start);

      printf("\n******************** FINISHED ********************\n");
      printf("  Sweeped %u of %u addresses - %5.2f%%\n", current, max_count, percentage);
      printf("  %zd IPs returned data - %5.2f%%\n", returnedData, data_percentage);
      printf("  Elapsed %lld seconds\n", elapsed.count());
      printf("\n**************************************************\n");
   }
   catch (std::exception & e)
   {
      printf("EXCEPTION: %s\n", e.what());
   }

   WSACleanup();

   system("pause");

   return 0;
}