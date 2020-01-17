#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <unordered_map>
#include <Windows.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include "DataStore.hpp"
#include "SSL_defs.h"
#include "sha256.hpp"


std::unordered_map<SHA256Hash, bool> map;

static size_t duplicates = 0;


static void dump(const char* label, const uint8_t* data, size_t len)
{
   printf("%s: ", label);
   for (size_t i = 0; i < len; ++i)
   {
      printf("%02X", data[i]);
   }
   printf("\n\n");
}


static bool ProcessCertificate(const uint8_t* data, size_t len, const long long ip)
{
   std::unique_ptr<X509, decltype(&X509_free)> cert(d2i_X509(NULL, &data, len), &X509_free);
   if (!cert)
   {
      //printf("Not a cert at all!\n");
      return false;
   }

   EVP_PKEY* public_key = X509_get0_pubkey(cert.get());
   if (!public_key)
   {
      if (data[0] == 0x00)
      {
         printf("Not a public key at %lld.%lld.%lld.%llu, but starts with 0x00\n", ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
      }
      else if (data[0] == 0x0E)
      {
         printf("Not a public key at %lld.%lld.%lld.%llu, but starts with 0x0E\n", ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
      }
      else
      {
         printf("Not a public key at %lld.%lld.%lld.%llu\n", ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
      }

      return false;
   }
   
   const RSA* rsa_key = EVP_PKEY_get0_RSA(public_key);   // Does not increment reference count
   if (rsa_key != nullptr)
   {
      int bits = RSA_bits(rsa_key);
      return true;
   }

   const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(public_key);   // Does not increment reference count
   if (ec_key != nullptr)
   {
      int bits = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
      if ((bits != 256) && (bits != 384) && (bits != 521))
      {
         printf("Strange EC keylen = %d\n", bits);
      }
            
      return true;
   }

   const DSA* dsa_key = EVP_PKEY_get0_DSA(public_key);
   if (dsa_key != nullptr)
   {
      int bits = DSA_bits(dsa_key);
      printf("DSA key with %d bits\n", bits);
      dump("DSA Key", data, len);
      return false;
   }
         
   const DH* dh_key = EVP_PKEY_get0_DH(public_key);
   if (dh_key != nullptr)
   {
      dump("DH Key", data, len);
      return false;
   }

   dump("Not RSA, EC, DSA nor DH", data, len);

   return false;
}


static size_t ProcessHandshakeMessage(const Handshake& handshake, const long long ip)
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

         SHA256Hash hash = SHA256::hash(&handshake.msg[i + 3], cert_len);
         auto ret = map.try_emplace(hash, true);
         if (ret.second)
         {
            if (ProcessCertificate(&handshake.msg[i + 3], cert_len, ip))
            {
               ++certs_found;
            }
         }
         else
         {
            ++duplicates;
         }
         
         //++certs_found;

         i += 3 + cert_len;
      }
   }

   return certs_found;
}


static size_t ProcessRecordMessage(const TLSPlaintext& record, const long long ip)
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

      certs_found += ProcessHandshakeMessage(handshake, ip);

      i += Handshake::HeaderSize + handshake.length;
   }

   return certs_found;
}


static size_t ParseResponse(const unsigned char* response, const int response_len, const long long ip)
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
         
         certs_found += ProcessRecordMessage(record, ip);

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
         const auto ret = ParseResponse(response, response_len, ip);
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