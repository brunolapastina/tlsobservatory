#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <unordered_map>
#include <Windows.h>
#include "DataStore.hpp"
#include "SSL_defs.h"
#include "sha256.hpp"


std::unordered_map<SHA256Hash, bool> map;

static size_t duplicates = 0;


static size_t ProcessHandshakeMessage(const Handshake& handshake)
{
   size_t certs_found = 0;

   //printf("   MsgType=%d  Length=%d\n", handshake.msg_type, handshake.length);
   if (handshake.msg_type == HandshakeType::certificate)
   {
      const uint32_t total_certs_len = (handshake.msg[0] << 16) | (handshake.msg[1] << 8) | handshake.msg[2];

      if (total_certs_len + 3 > handshake.length)
      {
         //printf("Corrupted handshake message\n");
         return certs_found;
      }

      for (uint32_t i = 3; i < 3 + total_certs_len; /* no increment */)
      {
         const uint32_t cert_len = (handshake.msg[i] << 16) | (handshake.msg[i + 1] << 8) | handshake.msg[i + 2];
         if (i + cert_len > 3 + total_certs_len)
         {
            //printf("Corrupted certificate\n");
            break;
         }

         /*printf("Certificate = ");
         for (uint32_t j = 0; j < cert_len; ++j)
         {
            printf("%02X", handshake.msg[i + 3 + j]);
         }
         printf("\n\n");*/

         SHA256Hash hash = SHA256::hash(&handshake.msg[i + 3], cert_len);
         auto ret = map.try_emplace(hash, true);
         if (ret.second)
         {
            ++certs_found;
         }
         else
         {
            ++duplicates;
         }

         i += 3 + cert_len;
      }
   }

   return certs_found;
}


static size_t ProcessRecordMessage(const TLSPlaintext& record)
{
   size_t certs_found = 0;

   //printf("Type=%d  Ver=%04X  Length=%d\n", record.type, record.legacy_record_version, record.length);
   for (int i = 0; i < record.length; /* no increment */)
   {
      Handshake handshake;

      handshake.msg_type = static_cast<HandshakeType>(record.fragment[i]);
      handshake.length = (record.fragment[i + 1] << 16) | (record.fragment[i + 2] << 8) | record.fragment[i + 3];
      handshake.msg = &record.fragment[i + 4];

      if (i + Handshake::HeaderSize + handshake.length > record.length)
      {
         //printf("Corrupted record message\n");
         return certs_found;
      }

      certs_found += ProcessHandshakeMessage(handshake);

      i += Handshake::HeaderSize + handshake.length;
   }

   return certs_found;
}


static size_t ParseResponse(const unsigned char* response, const int response_len)
{
   size_t certs_found = 0;

   for (int i = 0; i < response_len; /* no increment */)
   {
      if (response[i] == ContentType::handshake)
      {
         TLSPlaintext record;

         record.type = static_cast<ContentType>(response[i]);
         record.legacy_record_version = (response[i + 1] << 8) | response[i + 2];
         record.length = (response[i + 3] << 8) | response[i + 4];
         record.fragment = &response[i + 5];

         if (i + TLSPlaintext::HeaderSize + record.length > response_len)
         {
            //Corrupted message
            //printf("Corrupted response\n");
            return certs_found;
         }
         
         certs_found += ProcessRecordMessage(record);

         i += TLSPlaintext::HeaderSize + record.length;
      }
      else
      {
         //printf("Unknown record type - %d\n", response[i]);
         ++i;
      }
   }

   return certs_found;
}

int main()
{
   DataStore datastore;

   size_t no_response = 0;
   size_t invalid_response = 0;
   size_t valid_response = 0;
   size_t certs_found = 0;

   map.reserve(60000000);     // Reserve space for certs

   auto start = std::chrono::system_clock::now();

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
         ++no_response;
      }
      else if(response[0] == 0x16)
      {
         const auto ret = ParseResponse(response, response_len);
         certs_found += ret;
         valid_response += (ret > 0);
      }
      else
      {
         ++invalid_response;
      }

      if (std::chrono::system_clock::now() - start > std::chrono::seconds(10))
      {
         printf( "Partial  >>  Response[None:%8zd  Invalid:%8zd  Valid:%8zd]  Certs[Uniques:%8zd  Duplicates:%8zd]\n", no_response, invalid_response, valid_response, certs_found, duplicates);
         start = std::chrono::system_clock::now();
      }
   });

   printf("\n\n*** Total ***\n");
   printf("Response[None:%8zd  Invalid:%8zd  Valid:%8zd]  Certs[Uniques:%8zd  Duplicates:%8zd]\n\n", no_response, invalid_response, valid_response, certs_found, duplicates);

   return 0;
}