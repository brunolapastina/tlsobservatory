#pragma once
#include <memory>
#include <chrono>
#include <vector>
#include <string>
#include <cmath>
#include <system_error>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "base64.h"

using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SSL_ptr = std::unique_ptr<SSL, decltype(&SSL_free)>;

static const auto sock_timeout = std::chrono::milliseconds(5000);

extern SSL_CTX_ptr g_ssl_ctx;

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

   ConnSocket() : m_ssl(nullptr, SSL_free)
   {
      m_recv_data.reserve(6 * 1024);
      m_encoded_data.reserve(8 * 1024);   // Base64 data is 4/3 larger
   }

   bool is_connected() const noexcept
   {
      return (m_sock != INVALID_SOCKET);
   }

   bool connect(ULONG address, u_short port) noexcept
   {
      int ret;

      m_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (m_sock == INVALID_SOCKET)
      {
         printf("Error creating socket - LastError=%d\n", WSAGetLastError());
         return false;
      }

      LINGER lin{ 0,0 };
      ret = setsockopt(m_sock, SOL_SOCKET, SO_LINGER, (const char*)&lin, sizeof(lin));
      if (ret != 0)
      {
         printf("Error setting socket opt - LastError=%d\n", WSAGetLastError());
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
            printf("ioctlsocket failed - LastError=%d\n", WSAGetLastError());
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
      lastStateChange = std::chrono::system_clock::now();

      return true;
   }

   void disconnect() noexcept
   {
      shutdown(m_sock, SD_BOTH);
      closesocket(m_sock);
      m_sock = INVALID_SOCKET;
      m_ssl.reset();
   }

   WSAPOLLFD get_pollfd() const noexcept
   {
      return { m_sock, (m_state == State_e::Connecting) ? POLLOUT : POLLIN, 0 };
   }


   /**
    *Returns: 
    *    true when it is done comunicating with the socket
    *    false if there communication is still going on
    **/
   bool process_poll(WSAPOLLFD& fda)
   {
      if (fda.revents == 0)
      {  // Was not signaled. Did it timeout??
         const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - lastStateChange);
         if (elapsed > sock_timeout)
         {
            //printf("Timeout\n");
            return true;
         }
         else
         {
            return false;
         }
      }
      else if ((m_state == State_e::Connecting) && (fda.revents & POLLOUT))
      {
         m_ssl.reset(SSL_new(g_ssl_ctx.get()));
         SSL_set_connect_state(m_ssl.get());
         SSL_set_bio(m_ssl.get(), BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
         SSL_do_handshake(m_ssl.get());

         char outbuf[4096];
         int read = BIO_read(SSL_get_wbio(m_ssl.get()), outbuf, sizeof(outbuf));
         if (read <= 0)
         {
            printf("Error reading BIO\n");
            return true;
         }

         if (!send(outbuf, read))
         {
            printf("Error sending data\n");
            return true;
         }

         m_recv_data.clear();
         m_encoded_data.clear();
         lastStateChange = std::chrono::system_clock::now();
         m_state = State_e::WaitingReception;
         fda.revents = 0;
         fda.events = POLLIN;

         return false;
      }
      else if ((m_state == State_e::WaitingReception) && (fda.revents & POLLIN))
      {
         char outbuf[4096];
         int read = recv(outbuf, sizeof(outbuf));
         if (read > 0)
         {
            m_recv_data.insert(m_recv_data.end(), outbuf, outbuf + read);
            //printf("recv(%d) => ", read);
            //dump(outbuf, read);

            BIO_write(SSL_get_rbio(m_ssl.get()), outbuf, read);
         }

         SSL_do_handshake(m_ssl.get());
         fda.revents = 0;
         
         return (0 != BIO_pending(SSL_get_wbio(m_ssl.get())));
      }
      else if (fda.revents & POLLHUP)
      {
         return true;
      }
      else
      {
         printf("Signaled incorrectly\n");
         std::abort();
         return true;
      }
   }

   struct conn_result_t
   {
      unsigned long  ip;
      unsigned short port;
      const char* data;
      size_t data_len;
   };

   conn_result_t get_result() noexcept
   {
      base64::encode(m_recv_data, m_encoded_data);

      conn_result_t ret;
      ret.ip = 0;
      ret.port = 443;
      ret.data = m_encoded_data.data();
      ret.data_len = m_encoded_data.length();

      return ret;
   }

private:
   enum class State_e
   {
      Connecting,
      WaitingReception,
   };
   
   SOCKET m_sock = INVALID_SOCKET;
   SSL_ptr m_ssl;
   State_e  m_state = State_e::Connecting;
   std::chrono::time_point<std::chrono::system_clock> lastStateChange;

   std::vector<uint8_t> m_recv_data;
   std::string m_encoded_data;

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