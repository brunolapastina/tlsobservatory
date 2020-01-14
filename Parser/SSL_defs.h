#pragma once
#include <cstdint>

/*
 * Spec at https://tools.ietf.org/html/rfc8446
 */

enum ContentType : uint8_t
{
   invalid            = 0,
   change_cipher_spec = 20,
   alert              = 21,
   handshake          = 22,
   application_data   = 23,
   heartbeat          = 24,  /* RFC 6520 */
};