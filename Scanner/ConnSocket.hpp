#pragma once
#include <system_error>
#include <WinSock2.h>

class ConnSocket
{
public:
   ConnSocket()
   {
      m_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (m_sock == INVALID_SOCKET)
      {
         throw std::system_error(errno, std::generic_category(), "Error creating socket");
      }
      
      #ifdef _WIN32
         // Set the socket I/O mode: In this case FIONBIO enables or disables the 
         // blocking mode for the socket based on the numerical value of iMode.
         // If iMode = 0, blocking is enabled; 
         // If iMode != 0, non-blocking mode is enabled.

         u_long iMode = 1;
         int ret = ioctlsocket(m_sock, FIONBIO, &iMode);
         if (ret != NO_ERROR)
         {
            throw std::system_error(errno, std::generic_category(), "ioctlsocket failed");
         }
      #else
         fcntl(m_sock, F_SETFL, O_NONBLOCK);
      #endif
   }

   ConnSocket(const ConnSocket&) = delete;
   ConnSocket(ConnSocket&&) = default;
   ConnSocket& operator=(const ConnSocket&) = delete;
   ConnSocket& operator=(ConnSocket&&) = default;

   SOCKET get_fd() const noexcept { return m_sock; }

   bool connect(ULONG address, u_short port) noexcept
   {
      sockaddr_in clientService;
      clientService.sin_family = AF_INET;
      clientService.sin_addr.s_addr = address;
      clientService.sin_port = htons(port);

      int ret = ::connect(m_sock, reinterpret_cast<sockaddr*>(&clientService), sizeof(clientService));
      int err = WSAGetLastError();
      if ((ret != 0) && (err != WSAEWOULDBLOCK))
      {
         printf("Error connecting socket - ret=%d WSAGetLastError=%d\n", ret, err);
         return false;
      }

      return true;
   }

   bool send(const char* data, int len) noexcept
   {
      int ret = ::send(m_sock, data, len, 0);
      int err = WSAGetLastError();
      if (ret != len)
      {
         printf("Error sending data - ret=%d WSAGetLastError=%d\n", ret, err);
         return false;
      }
   }

   int recv(char* data, int maxlen) noexcept
   {
      int ret = ::recv(m_sock, data, maxlen, 0);
      return ret;
   }

   ~ConnSocket() noexcept
   {
      closesocket(m_sock);
   }

private:
   SOCKET m_sock = INVALID_SOCKET;
};

