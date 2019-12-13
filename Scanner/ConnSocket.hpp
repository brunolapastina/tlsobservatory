#pragma once
#include <memory>
#include <chrono>
#include <vector>
#include <string>
#include <cmath>
#include <system_error>
#ifdef _WIN32
   #include <WinSock2.h>
   #define poll            WSAPoll
   #define pollfd          WSAPOLLFD
   #define SHUT_RDWR       SD_BOTH
   #define WOULDBLOCK_DEF  WSAEWOULDBLOCK
#else
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <netinet/tcp.h>
   #include <arpa/inet.h>
   #include <poll.h>
   #include <unistd.h>
   #include <fcntl.h>
   #define INVALID_SOCKET  -1
   #define closesocket     close
   #define WOULDBLOCK_DEF  EWOULDBLOCK
   typedef int SOCKET;
   static inline auto WSAGetLastError() { return errno; }
   static unsigned long long GetTickCount64()
   {
      static_assert(sizeof(std::time_t) == 8, "time_t variable is not 64 bits");
      struct timespec ts;
      clock_gettime( CLOCK_MONOTONIC, &ts );
      unsigned long long ticks  = ts.tv_nsec / 1000000;
      ticks += ts.tv_sec * 1000;
      return ticks;
   }
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SSL_ptr = std::unique_ptr<SSL, decltype(&SSL_free)>;

static constexpr auto sock_timeout = 5000;

extern SSL_CTX_ptr g_ssl_ctx;

class ConnSocket
{
public:
   ConnSocket(const ConnSocket&) = delete;
   ConnSocket(ConnSocket&&) = default;
   ConnSocket& operator=(const ConnSocket&) = delete;
   ConnSocket& operator=(ConnSocket&&) = default;

   ConnSocket() : m_ssl(nullptr, SSL_free),
                  m_lastStateChange{ 0 }
   {
      m_recv_data.reserve(6 * 1024);
   }

   bool is_connected() const noexcept
   {
      return (m_sock != INVALID_SOCKET);
   }

   bool connect(unsigned long address, unsigned short port) noexcept
   {
      int ret;

      m_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (m_sock == INVALID_SOCKET)
      {
         printf("Error creating socket - LastError=%d\n", WSAGetLastError());
         return false;
      }

      #ifdef _WIN32
         LINGER lin{ 0,0 };
         ret = setsockopt(m_sock, SOL_SOCKET, SO_LINGER, (const char*)&lin, sizeof(lin));
         if (ret != 0)
         {
            printf("Error setting socket opt - LastError=%d\n", WSAGetLastError());
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
            return false;
         }

         // Set the socket I/O mode: In this case FIONBIO enables or disables the 
         // blocking mode for the socket based on the numerical value of iMode.
         // If iMode = 0, blocking is enabled; 
         // If iMode != 0, non-blocking mode is enabled.
         unsigned long iMode = 1;
         ret = ioctlsocket(m_sock, FIONBIO, &iMode);
         if (ret != NO_ERROR)
         {
            printf("ioctlsocket failed - LastError=%d\n", WSAGetLastError());
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
            return false;
         }
      #else
         fcntl(m_sock, F_SETFL, O_NONBLOCK);
      #endif

      m_address = address;
      m_port = port;

      sockaddr_in clientService;
      clientService.sin_family = AF_INET;
      clientService.sin_addr.s_addr = ntohl(m_address);
      clientService.sin_port = htons(m_port);

      ret = ::connect(m_sock, reinterpret_cast<sockaddr*>(&clientService), sizeof(clientService));
      const auto err = WSAGetLastError();
      if ((ret != 0) && (err != WOULDBLOCK_DEF))
      {
         printf("Error connecting socket - ret=%d WSAGetLastError=%d\n", ret, err);
         closesocket(m_sock);
         m_sock = INVALID_SOCKET;
         return false;
      }

      m_state = State_e::Connecting;
      m_lastStateChange = GetTickCount64();

      return true;
   }

   void disconnect() noexcept
   {
      shutdown(m_sock, SHUT_RDWR);
      closesocket(m_sock);
      m_sock = INVALID_SOCKET;
      m_ssl.reset();
      m_recv_data.clear();
   }

   pollfd get_pollfd() const noexcept
   {
      return { m_sock, static_cast<short>((m_state == State_e::Connecting) ? POLLOUT : POLLIN), 0 };
   }


   /**
    *Returns: 
    *    true when it is done comunicating with the socket
    *    false if there communication is still going on
    **/
   bool process_poll(pollfd& fda)
   {
      if (fda.revents == 0)
      {  // Was not signaled. Did it timeout??
         const auto elapsed = (GetTickCount64() - m_lastStateChange);
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

         m_lastStateChange = GetTickCount64();
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
      int            result;
      const uint8_t* data;
      size_t         data_len;
   };

   conn_result_t get_result() noexcept
   {
      conn_result_t ret;
      ret.ip       = m_address;
      ret.port     = m_port;
      ret.result   = 0;
      ret.data     = m_recv_data.data();
      ret.data_len = m_recv_data.size();

      return ret;
   }

private:
   enum class State_e
   {
      Connecting,
      WaitingReception,
   };

   enum class Result_e
   {
      ConnectionFailed,
      TLSError
   };
   
   unsigned long m_address = 0;
   u_short m_port = 0;
   SOCKET m_sock = INVALID_SOCKET;
   SSL_ptr m_ssl;
   State_e  m_state = State_e::Connecting;
   unsigned long long m_lastStateChange;

   std::vector<uint8_t> m_recv_data;

   bool send(const char* data, int len) noexcept
   {
      int ret = ::send(m_sock, data, len, 0);
      const auto err = WSAGetLastError();
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