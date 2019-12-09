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

   const size_t concurrency = 100;
   std::vector<ConnSocket> socks(concurrency);
   std::vector<WSAPOLLFD>  fdas(concurrency);
   int curr_address = 1;

   while(true)
   {
      bool is_there_active_conn = false;
      for (int i = 0; i < socks.size(); ++i)
      {
         if (socks[i].is_connected())
         {
            is_there_active_conn = true;
         }
         else if(curr_address < 255 )
         {
            char address[20];
            sprintf_s(address, "200.147.118.%d", curr_address);
            printf("Testing %s\n", address);
            if (!socks[i].connect(inet_addr(address), 443))
            {
               printf("Error connecting socket\n");
            }
            else
            {
               ++curr_address;
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
      //printf("Poll returned %d\n", ret);
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
   }

   /*for (int i = 1; i < 255; ++i)
   {
      char address[64];
      sprintf_s(address, "200.147.118.%d", i);
      printf("testing ip %s\n", address);

      ConnSocket conn;

      if (!conn.connect(inet_addr(address), 443))
      {
         printf("Error connecting socket\n");
         return 1;
      }

      while (true)
      {
         auto fda = conn.get_pollfd();
         int ret = WSAPoll(&fda, 1, 5000);
         if (ret < 0)
         {
            printf("WSAPoll error\n");
            break;
         }
         else if (ret == 0)
         {
            printf("WSAPoll timeout\n");
            break;
         }
         else if (!(fda.revents & fda.events))
         {
            printf("WSAPoll signaled incorrectly - ret=%d - revents=%X\n", ret, fda.revents);
            break;
         }
         else
         {
            if (!conn.process_poll())
            {
               break;
            }
         }
      }
   }*/

   WSACleanup();

   return 0;
}