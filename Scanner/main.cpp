#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>
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
   //SSL_CTX_ptr ssl_ctx(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);

   WSADATA wsaData = { 0 };
   int iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
   if (iRet != 0)
   {
      wprintf(L"WSAStartup failed: %d\n", iRet);
      return 1;
   }

   for (int i = 1; i < 255; ++i)
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
   }

   WSACleanup();

   return 0;
}