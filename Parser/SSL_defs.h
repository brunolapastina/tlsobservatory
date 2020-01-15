#pragma once
#include <cstdint>

/*
 * Spec at https://tools.ietf.org/html/rfc8446
 */

#pragma pack(push, 1)

typedef uint16_t ProtocolVersion;

enum ContentType : uint8_t
{
   invalid            = 0,
   change_cipher_spec = 20,
   alert              = 21,
   handshake          = 22,
   application_data   = 23,
   heartbeat          = 24,  /* RFC 6520 */
};

struct TLSPlaintext 
{
   ContentType type;
   ProtocolVersion legacy_record_version;
   uint16_t length;
   const uint8_t* fragment;

   static const size_t HeaderSize = sizeof(type) + sizeof(legacy_record_version) + sizeof(length);
};


enum HandshakeType : uint8_t
{
   hello_request_RESERVED = 0,
   client_hello = 1,
   server_hello = 2,
   hello_verify_request_RESERVED = 3,
   new_session_ticket = 4,
   end_of_early_data = 5,
   hello_retry_request_RESERVED = 6,
   encrypted_extensions = 8,
   certificate = 11,
   server_key_exchange_RESERVED = 12,
   certificate_request = 13,
   server_hello_done_RESERVED = 14,
   certificate_verify = 15,
   client_key_exchange_RESERVED = 16,
   finished = 20,
   certificate_url_RESERVED = 21,
   certificate_status_RESERVED = 22,
   supplemental_data_RESERVED = 23,
   key_update = 24,
   message_hash = 254,   
};

struct Handshake 
{
   HandshakeType  msg_type;
   uint32_t       length;
   const uint8_t* msg;

   static const size_t HeaderSize = sizeof(msg_type) + /*sizeof(length) is actually 3 bytes*/ 3;
};

#pragma pack(pop)