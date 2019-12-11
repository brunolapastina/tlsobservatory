#pragma once
#include <stdexcept>
#include "sqlite3.h"

static constexpr char create_table_query[]
{
   "CREATE TABLE IF NOT EXISTS raw_data (ip INTEGER, port MEDIUMINT, fetchTime UNSIGNED INTEGER, result INTEGER, response VARCHAR)"
};

static constexpr char begin_transaction_query[]
{
   "BEGIN"
};

static constexpr char commit_transaction_query[]
{
   "COMMIT"
};

static constexpr char insert_record_query[]
{
   "INSERT INTO raw_data (ip, port, fetchTime, result, response) values (?, ?, ?, ?, ?)"
};

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

      rc = sqlite3_exec( m_db, create_table_query, nullptr, nullptr, nullptr );
      if (rc != SQLITE_OK)
      {
         throw std::runtime_error(std::string("sqlite3_exec(create table) error: ") + sqlite3_errmsg(m_db));
      }

      rc = sqlite3_prepare_v2(m_db, begin_transaction_query, strlen(begin_transaction_query), &m_begin_stml, nullptr);
      if (rc != SQLITE_OK)
      {
         throw std::runtime_error(std::string("sqlite3_prepare_v2(begin) error: ") + sqlite3_errmsg(m_db));
      }

      rc = sqlite3_prepare_v2(m_db, commit_transaction_query, strlen(commit_transaction_query), &m_commit_stml, nullptr);
      if (rc != SQLITE_OK)
      {
         throw std::runtime_error(std::string("sqlite3_prepare_v2(commit) error: ") + sqlite3_errmsg(m_db));
      }

      rc = sqlite3_prepare_v2(m_db, insert_record_query, strlen(insert_record_query), &m_insert_stml, nullptr);
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
      int rc = sqlite3_step(m_begin_stml);
      if (SQLITE_DONE != rc)
      {
         printf("sqlite3_step(begin) error: %s\n", sqlite3_errmsg(m_db));
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

      return true;
   }

   bool insert(unsigned long ip, unsigned short port, int result, const char* data, size_t data_len)
   {
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

      SYSTEMTIME sysTime;
      FILETIME   fileTime;
      GetLocalTime(&sysTime);
      SystemTimeToFileTime(&sysTime, &fileTime);
      ULARGE_INTEGER timestamp;
      timestamp.HighPart = fileTime.dwHighDateTime;
      timestamp.LowPart = fileTime.dwLowDateTime;

      rc = sqlite3_bind_int(m_insert_stml, 3, timestamp.QuadPart);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_int(port) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      rc = sqlite3_bind_int64(m_insert_stml, 4, result);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_bind_int64(result) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      rc = sqlite3_bind_text(m_insert_stml, 5, data, data_len, SQLITE_STATIC);
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
   sqlite3* m_db = nullptr;
   sqlite3_stmt* m_insert_stml = nullptr;
   sqlite3_stmt* m_begin_stml = nullptr;
   sqlite3_stmt* m_commit_stml = nullptr;
};
