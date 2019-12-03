#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <cstdio>
#include <cstdlib>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


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

   WSADATA wsaData = { 0 };
   int iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
   if (iRet != 0)
   {
      wprintf(L"WSAStartup failed: %d\n", iRet);
      return 1;
   }

   SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   if (sock == INVALID_SOCKET)
   {
      printf("Error creating socket\n");
      return 1;
   }

   sockaddr_in clientService;
   clientService.sin_family = AF_INET;
   clientService.sin_addr.s_addr = inet_addr("200.147.118.40");
   clientService.sin_port = htons(443);

   iRet = connect(sock, reinterpret_cast<sockaddr*>(&clientService), sizeof(clientService));
   if (iRet != 0)
   {
      printf("Error connecting socket\n");
      return 1;
   }

   printf("Connected\n");

   SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
   SSL* ssl = SSL_new(ctx);
   if (!ssl)
   {
      printf("Error creating SSL.\n");
      log_ssl();
      return -1;
   }

   SSL_set_connect_state(ssl);
   SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
   SSL_do_handshake(ssl);

   while (!SSL_is_init_finished(ssl))
   {
      char outbuf[4096];
      int written = 0;
      int read = BIO_read(SSL_get_wbio(ssl), outbuf, sizeof(outbuf));
      if (read > 0)
      {
         printf("BIO_read(%d) => ", read);
         dump(outbuf, read);

         int ret = send(sock, outbuf, read, 0);
         if (ret != read)
         {
            printf("Error sending data\n");
         }
      }

      read = recv(sock, outbuf, sizeof(outbuf), 0);
      if (read > 0)
      {
         printf("recv(%d) => ", read);
         dump(outbuf, read);

         BIO_write(SSL_get_rbio(ssl), outbuf, read);
      }

      SSL_do_handshake(ssl);
   }

   SSL_free(ssl);
   SSL_CTX_free(ctx);

   closesocket(sock);

   WSACleanup();

   return 0;
}