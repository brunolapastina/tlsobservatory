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


static void log_ssl()
{
   int err;
   while (err = ERR_get_error()) {
      char* str = ERR_error_string(err, 0);
      if (!str)
         return;
      printf(str);
      printf("\n");
      fflush(stdout);
   }
}


int main()
{
   SSL_library_init();
   SSLeay_add_ssl_algorithms();
   SSL_load_error_strings();

   WSADATA wsaData = { 0 };
   int iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
   if (iRet != 0)
   {
      wprintf(L"WSAStartup failed: %d\n", iRet);
      return 1;
   }

   const size_t concurrency = 1000;
   std::vector<ConnSocket> socks(concurrency);
   std::vector<WSAPOLLFD>  fdas(concurrency);
   IPSpaceSweeper ip_range;

   //ip_range.add_range("200.147.118.0", 24);
   ip_range.add_range("200.147.116.0", 22);

   const auto stat_interval = std::chrono::seconds(2);
   const auto start = std::chrono::system_clock::now();
   auto last_stat = start;
   while(true)
   {
      bool is_there_active_conn = false;
      for (int i = 0; i < socks.size(); ++i)
      {
         if (socks[i].is_connected())
         {
            is_there_active_conn = true;
         }
         else if(!ip_range.has_range_finished())
         {
            const auto ip = ip_range.get_ip();
            //printf("Testing %d.%d.%d.%d\n", ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
            if (!socks[i].connect(ip, 443))
            {
               printf("Error connecting socket\n");
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
         for (int i = 0; i < socks.size(); ++i)
         {
            if (!socks[i].process_poll(fdas[i]))
            {
               socks[i].disconnect();
            }
         }
      }

      if ((std::chrono::system_clock::now() - last_stat) >= stat_interval)
      {
         const auto [current, max_count] = ip_range.get_stats();
         const float percentage = (100.0 * current) / max_count;
         const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - start);
         const auto remaining = ((elapsed.count() * 100.0) / percentage) - elapsed.count();

         printf("\n******************** PROGRESS ********************\n");
         printf("  Sweeped %u of %u addresses - That is %4.1f%%\n", current, max_count, percentage);
         printf("  Elapsed %lld seconds\n", elapsed.count());
         printf("  Estimated remaining time: %.0f seconds\n", remaining);

         last_stat = std::chrono::system_clock::now();
      }
   }

   WSACleanup();

   return 0;
}