#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#include "DataStore.hpp"


int main()
{
   DataStore datastore;

   size_t success = 0;
   size_t error = 0;
   size_t invalid = 0;

   datastore.for_each_row("SELECT ip, port, fetchTime, result, response from raw_data", [&](sqlite3_stmt* stml)
   {
         const long long ip                 = sqlite3_column_int64(stml, 0);
         const unsigned int port            = sqlite3_column_int(stml, 1);
         const unsigned long long fetchTime = sqlite3_column_int64(stml, 2);
         const long long result             = sqlite3_column_int64(stml, 3);
         const unsigned char* response      = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stml, 4));
         const int response_len             = sqlite3_column_bytes(stml, 4);

         //printf( "%lld.%lld.%lld.%llu:%u  Result=%lld  ResponseLen=%d\n", ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24, port, result, response_len);

         if (response_len == 0)
         {
            ++invalid;
         }
         else if(response[0] == 0x16)
         {
            ++success;
         }
         else
         {
            ++error;
         }
   });

   printf("Valid   = %zd\n", success);
   printf("Error   = %zd\n", error);
   printf("Invalid = %zd\n", invalid);

   Sleep(5000);

   return 0;
}