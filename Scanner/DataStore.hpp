#pragma once
#include <stdexcept>
#include <string_view>
#include <mutex>
#include "sqlite3.h"
#include "ConnSocket.hpp"

static constexpr std::string_view query_create_table{
   "CREATE TABLE IF NOT EXISTS raw_data (ip INTEGER, port MEDIUMINT, fetchTime UNSIGNED INTEGER, result INTEGER, response BLOB)"
};

static constexpr std::string_view query_begin_transaction{ "BEGIN" };

static constexpr std::string_view query_commit_transaction{ "COMMIT" };

static constexpr std::string_view query_insert_record{
   "INSERT INTO raw_data (ip, port, fetchTime, result, response) values (?, ?, ?, ?, ?)"
};


static unsigned long long GetTimstamp()
{
#ifdef _WIN32
   SYSTEMTIME sysTime;
   FILETIME   fileTime;
   GetLocalTime(&sysTime);
   SystemTimeToFileTime(&sysTime, &fileTime);
   ULARGE_INTEGER timestamp;
   timestamp.HighPart = fileTime.dwHighDateTime;
   timestamp.LowPart = fileTime.dwLowDateTime;

   return timestamp.QuadPart;
#else
   #error GetTimstamp not implemented
   return 0;
#endif
}


class DataStore
{
public:
   DataStore()
   {
      int rc = sqlite3_open("tls_observatory.db", &m_db);
      if (rc)
      {
         throw std::runtime_error(std::string("Can't open database: ") + sqlite3_errmsg(m_db));
      }

      rc = sqlite3_exec( m_db, query_create_table.data(), nullptr, nullptr, nullptr );
      if (rc != SQLITE_OK)
      {
         throw std::runtime_error(std::string("sqlite3_exec(create table) error: ") + sqlite3_errmsg(m_db));
      }

      rc = sqlite3_prepare_v2(m_db, query_begin_transaction.data(), static_cast<int>(query_begin_transaction.size()), &m_begin_stml, nullptr);
      if (rc != SQLITE_OK)
      {
         throw std::runtime_error(std::string("sqlite3_prepare_v2(begin) error: ") + sqlite3_errmsg(m_db));
      }

      rc = sqlite3_prepare_v2(m_db, query_commit_transaction.data(), static_cast<int>(query_commit_transaction.size()), &m_commit_stml, nullptr);
      if (rc != SQLITE_OK)
      {
         throw std::runtime_error(std::string("sqlite3_prepare_v2(commit) error: ") + sqlite3_errmsg(m_db));
      }

      rc = sqlite3_prepare_v2(m_db, query_insert_record.data(), static_cast<int>(query_insert_record.size()), &m_insert_stml, nullptr);
      if (rc != SQLITE_OK)
      {
         throw std::runtime_error(std::string("sqlite3_prepare_v2(insert) error: ") + sqlite3_errmsg(m_db));
      }
   }

   ~DataStore()
   {
      int rc = sqlite3_finalize(m_insert_stml);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_finalize(insert) error: %s\n", sqlite3_errmsg(m_db));
      }

      rc = sqlite3_finalize(m_commit_stml);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_finalize(commit) error: %s\n", sqlite3_errmsg(m_db));
      }

      rc = sqlite3_finalize(m_begin_stml);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_finalize(begin) error: %s\n", sqlite3_errmsg(m_db));
      }

      sqlite3_close(m_db);
   }

   bool begin()
   {
      m_transaction_lock.lock();
      int rc = sqlite3_step(m_begin_stml);
      if (SQLITE_DONE != rc)
      {
         printf("sqlite3_step(begin) error: %s\n", sqlite3_errmsg(m_db));
         m_transaction_lock.unlock();
         return false;
      }

      sqlite3_clear_bindings(m_begin_stml);
      sqlite3_reset(m_begin_stml);

      return true;
   }

   bool commit()
   {
      int rc = sqlite3_step(m_commit_stml);
      if (SQLITE_DONE != rc)
      {
         printf("sqlite3_step(commit) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      sqlite3_clear_bindings(m_commit_stml);
      sqlite3_reset(m_commit_stml);

      m_transaction_lock.unlock();

      return true;
   }

   bool insert(unsigned long ip, unsigned short port, ConnSocket::Result_e result, const uint8_t* data, size_t data_len)
   {
      if (result == ConnSocket::Result_e::TCPHandshakeTimeout)
      {  // Does not store host that didn't answer
         return true;
      }

      int rc = sqlite3_bind_int64(m_insert_stml, 1, ip);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_int64(ip) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      rc = sqlite3_bind_int(m_insert_stml, 2, port);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_int(port) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      rc = sqlite3_bind_int64(m_insert_stml, 3, GetTimstamp());
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_int(port) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      rc = sqlite3_bind_int64(m_insert_stml, 4, static_cast<int>(result));
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_int64(result) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      rc = sqlite3_bind_blob64(m_insert_stml, 5, data, data_len, SQLITE_STATIC);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_text(response) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

		rc = sqlite3_step(m_insert_stml);
		if (SQLITE_DONE != rc)
		{
         printf("sqlite3_step(insert) error: %s\n", sqlite3_errmsg(m_db));
         return false;
		}

      sqlite3_clear_bindings(m_insert_stml);
      sqlite3_reset(m_insert_stml);

      return true;
   }

private:
   std::mutex m_transaction_lock;
   sqlite3* m_db = nullptr;
   sqlite3_stmt* m_insert_stml = nullptr;
   sqlite3_stmt* m_begin_stml = nullptr;
   sqlite3_stmt* m_commit_stml = nullptr;
};
