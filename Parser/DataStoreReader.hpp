#pragma once
#include <stdexcept>
#include <string_view>
#include "sqlite3.h"

class DataStoreReader
{
public:
   DataStoreReader()
   {
      int rc = sqlite3_open("tls_observatory.db", &m_db);
      if (rc)
      {
         throw std::runtime_error(std::string("Can't open database: ") + sqlite3_errmsg(m_db));
      }
   }

   ~DataStoreReader()
   {
      sqlite3_close(m_db);
   }

   template<typename T>
   bool for_each_row(const std::string_view query, T row_parse_func)
   {
      sqlite3_stmt* query_stml = nullptr;
      int rc = sqlite3_prepare_v2(m_db, query.data(), static_cast<int>(query.size()), &query_stml, nullptr);
      if (rc != SQLITE_OK)
      {
         printf("sqlite3_prepare_v2(insert) error: %s\n", sqlite3_errmsg(m_db));
         return false;
      }

      while (true)
      {
         rc = sqlite3_step(query_stml);
         if (SQLITE_ROW == rc)
         {
            row_parse_func(query_stml);
         }
         else
         {
            if (SQLITE_DONE != rc)
            {
               printf("sqlite3_step error: %s\n", sqlite3_errmsg(m_db));
            }

            rc = sqlite3_finalize(query_stml);
            if (rc != SQLITE_OK)
            {
               printf("sqlite3_finalize error: %s\n", sqlite3_errmsg(m_db));
               break;
            }
            break;
         }
      }

      return true;
   }

private:
   sqlite3* m_db = nullptr;
};
