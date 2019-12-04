#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ConnSocket.hpp"

using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SSL_ptr = std::unique_ptr<SSL, decltype(&SSL_free)>;

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


static void dump(const char* data, const int len)
{
   for (int i = 0; i < len; ++i)
   {
      printf("%02X ", (unsigned char)data[i]);
   }
   printf("\n\n");
}




int main()
{
   SSL_library_init();
   SSLeay_add_ssl_algorithms();
   SSL_load_error_strings();
   SSL_CTX_ptr ssl_ctx(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);

   WSADATA wsaData = { 0 };
   int iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
   if (iRet != 0)
   {
      wprintf(L"WSAStartup failed: %d\n", iRet);
      return 1;
   }

   ConnSocket conn;

   if (!conn.connect(inet_addr("200.147.118.40"), 443))
   {
      printf("Error connecting socket\n");
      return 1;
   }

   WSAPOLLFD fda{ conn.get_fd(), POLLOUT, 0};

   int ret = WSAPoll( &fda, 1,5000 );
   if (ret <= 0)
   {
      printf("WSAPoll error\n");
      return 1;
   }
   else if (!(fda.revents & POLLOUT))
   {
      printf("WSAPoll signaled incorrectly - ret=%d\n", ret);
      return 1;
   }

   fda.events = POLLIN;
   fda.revents = 0;

   SSL_ptr ssl(SSL_new(ssl_ctx.get()), SSL_free);
   if (!ssl)
   {
      printf("Error creating SSL.\n");
      log_ssl();
      return -1;
   }

   SSL_set_connect_state(ssl.get());
   SSL_set_bio(ssl.get(), BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
   SSL_do_handshake(ssl.get());

   char outbuf[4096];
   int read = BIO_read(SSL_get_wbio(ssl.get()), outbuf, sizeof(outbuf));
   if (read <= 0)
   {
      printf("Error reading BIO\n");
      return 1;
   }
   
   if( !conn.send(outbuf, read) )
   {
      printf("Error sending data\n");
      return 1;
   }

   while (0 == BIO_pending(SSL_get_wbio(ssl.get())))
   {
      int ret = WSAPoll(&fda, 1, 5000);
      if (ret <= 0)
      {
         printf("WSAPoll error\n");
         return 1;
      }
      else if (!(fda.revents & POLLIN))
      {
         printf("WSAPoll signaled incorrectly - ret=%d - revents=%X\n", ret, fda.revents);
         //return 1;
      }
      else
      {
         read = conn.recv(outbuf, sizeof(outbuf));
         if (read > 0)
         {
            printf("recv(%d) => ", read);
            dump(outbuf, read);

            BIO_write(SSL_get_rbio(ssl.get()), outbuf, read);
         }

         SSL_do_handshake(ssl.get());
         fda.revents = 0;
      }
   }

   WSACleanup();

   return 0;
}