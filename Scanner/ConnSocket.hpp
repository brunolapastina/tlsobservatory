#pragma once
#include <memory>
#include <system_error>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SSL_ptr = std::unique_ptr<SSL, decltype(&SSL_free)>;


static void dump(const char* data, const int len)
{
   for (int i = 0; i < len; ++i)
   {
      printf("%02X ", (unsigned char)data[i]);
   }
   printf("\n\n");
}


class ConnSocket
{
public:
   ConnSocket(const ConnSocket&) = delete;
   ConnSocket(ConnSocket&&) = default;
   ConnSocket& operator=(const ConnSocket&) = delete;
   ConnSocket& operator=(ConnSocket&&) = default;

   ConnSocket() : m_ssl(nullptr, SSL_free) {}

   ~ConnSocket() noexcept
   {
      closesocket(m_sock);
   }

   bool connect(ULONG address, u_short port) noexcept
   {
      int ret;

      m_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (m_sock == INVALID_SOCKET)
      {
         printf("Error creating socket\n");
         return false;
      }

      #ifdef _WIN32
         // Set the socket I/O mode: In this case FIONBIO enables or disables the 
         // blocking mode for the socket based on the numerical value of iMode.
         // If iMode = 0, blocking is enabled; 
         // If iMode != 0, non-blocking mode is enabled.

         u_long iMode = 1;
         ret = ioctlsocket(m_sock, FIONBIO, &iMode);
         if (ret != NO_ERROR)
         {
            printf("ioctlsocket failed\n");
            return false;
         }
      #else
         fcntl(m_sock, F_SETFL, O_NONBLOCK);
      #endif

      sockaddr_in clientService;
      clientService.sin_family = AF_INET;
      clientService.sin_addr.s_addr = address;
      clientService.sin_port = htons(port);

      ret = ::connect(m_sock, reinterpret_cast<sockaddr*>(&clientService), sizeof(clientService));
      int err = WSAGetLastError();
      if ((ret != 0) && (err != WSAEWOULDBLOCK))
      {
         printf("Error connecting socket - ret=%d WSAGetLastError=%d\n", ret, err);
         return false;
      }

      m_state = State_e::Connecting;

      return true;
   }

   WSAPOLLFD get_pollfd() const noexcept
   {
      return { m_sock, (m_state == State_e::Connecting) ? POLLOUT : POLLIN, 0 };
   }

   bool process_poll()
   {
      if (m_state == State_e::Connecting)
      {
         //SSL_CTX_ptr ssl_ctx(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);
         m_ssl = SSL_ptr(SSL_new(ssl_ctx.get()), SSL_free);
         SSL_set_connect_state(m_ssl.get());
         SSL_set_bio(m_ssl.get(), BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
         SSL_do_handshake(m_ssl.get());

         char outbuf[4096];
         int read = BIO_read(SSL_get_wbio(m_ssl.get()), outbuf, sizeof(outbuf));
         if (read <= 0)
         {
            printf("Error reading BIO\n");
            return false;
         }

         //printf("send(%d) => ", read);
         //dump(outbuf, read);

         if (!send(outbuf, read))
         {
            printf("Error sending data\n");
            return false;
         }

         m_state = State_e::WaitingReception;

         return true;
      }
      else //if (m_state == State_e::WaitingReception)
      {
         char outbuf[4096];
         int read = recv(outbuf, sizeof(outbuf));
         if (read > 0)
         {
            printf("recv(%d) => ", read);
            dump(outbuf, read);

            BIO_write(SSL_get_rbio(m_ssl.get()), outbuf, read);
         }

         SSL_do_handshake(m_ssl.get());
         
         return (0 == BIO_pending(SSL_get_wbio(m_ssl.get())));
      }
   }

private:
   static SSL_CTX_ptr ssl_ctx;

   enum class State_e
   {
      Connecting,
      WaitingReception,
   };
   
   SOCKET m_sock = INVALID_SOCKET;
   SSL_ptr m_ssl;
   State_e  m_state = State_e::Connecting;

   bool send(const char* data, int len) noexcept
   {
      int ret = ::send(m_sock, data, len, 0);
      int err = WSAGetLastError();
      if (ret != len)
      {
         printf("Error sending data - ret=%d WSAGetLastError=%d\n", ret, err);
         return false;
      }

      return true;
   }

   int recv(char* data, int maxlen) noexcept
   {
      int ret = ::recv(m_sock, data, maxlen, 0);
      return ret;
   }
};

SSL_CTX_ptr ConnSocket::ssl_ctx(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);