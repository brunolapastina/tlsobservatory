#pragma once
#include <stdexcept>
#include <string_view>
#include <mutex>
#include "sqlite3.h"


static unsigned long long GetTimestamp()
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


enum class KeyType_t
{
   RSA = 0,
   EC  = 1,
   DSA = 2,
   DH  = 3
};


class DataStoreWriter
{
public:
   DataStoreWriter()
   {
      int rc = sqlite3_open("certs.db", &m_db);
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

   ~DataStoreWriter()
   {
      if (m_isDuringTransaction)
      {
         commit_transaction();
      }
      
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

   bool begin_transaction() noexcept
   {
      if (m_isDuringTransaction)
      {
         return true;
      }

      int rc = sqlite3_step(m_begin_stml);
      if (SQLITE_DONE != rc)
      {
         printf("sqlite3_step(begin) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      sqlite3_clear_bindings(m_begin_stml);
      sqlite3_reset(m_begin_stml);

      m_transactionStart = GetTimestamp();
      m_isDuringTransaction = true;

      return true;
   }

   bool commit_transaction() noexcept
   {
      std::unique_lock<std::mutex> lck(m_transaction_lock);
      return commit_transaction_int();
   }

   bool check_commit_interval() noexcept
   {
      const auto transaction_duration = (GetTimestamp() - m_transactionStart) / 10000; // Convert elapsed from 10s of nanoseconds to ms
      if (transaction_duration >= max_transaction_duration)
      {
         //printf("Commiting after %llu ms\n", transaction_duration);
         if (!commit_transaction_int())
         {
            printf("Error commiting current transation\n");
            return false;
         }

         if (!begin_transaction())
         {
            printf("begin_transaction error\n");
            return false;
         }
      }

      return true;
   }

   bool insert(KeyType_t type, int bitLen, const uint8_t* data, size_t data_len) noexcept
   {
      std::unique_lock<std::mutex> lck(m_transaction_lock);

      int rc = sqlite3_bind_int(m_insert_stml, 1, static_cast<int>(type));
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_int64(ip) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      rc = sqlite3_bind_int(m_insert_stml, 2, bitLen);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_int(port) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      rc = sqlite3_bind_blob64(m_insert_stml, 3, data, data_len, SQLITE_STATIC);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_text(response) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      if (!begin_transaction())
      {
         printf("begin_transaction error\n");
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

      if (!check_commit_interval())
      {
         printf("Error during checking commit interval\n");
         return false;
      }

      return true;
   }

private:
   static constexpr unsigned long long max_transaction_duration = 5000;
   static constexpr std::string_view query_begin_transaction{ "BEGIN TRANSACTION" };
   static constexpr std::string_view query_commit_transaction{ "COMMIT" };
   static constexpr std::string_view query_create_table{ 
      "CREATE TABLE IF NOT EXISTS certificates (KeyType INTEGER, BitLen INTEGER, Data BLOB)"
   };
   static constexpr std::string_view query_insert_record{
      "INSERT INTO certificates (KeyType, BitLen, Data) values (?, ?, ?)"
   };

   std::mutex m_transaction_lock;
   bool m_isDuringTransaction = false;
   unsigned long long m_transactionStart = 0;
   sqlite3* m_db = nullptr;
   sqlite3_stmt* m_insert_stml = nullptr;
   sqlite3_stmt* m_begin_stml = nullptr;
   sqlite3_stmt* m_commit_stml = nullptr;

   bool commit_transaction_int() noexcept
   {
      if (!m_isDuringTransaction)
      {
         return true;
      }

      int rc = sqlite3_step(m_commit_stml);
      if (SQLITE_DONE != rc)
      {
         printf("sqlite3_step(commit) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      sqlite3_clear_bindings(m_commit_stml);
      sqlite3_reset(m_commit_stml);

      m_isDuringTransaction = false;

      return true;
   }
};
