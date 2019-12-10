//
//  base64 encoding and decoding with C++.
//  Version: 1.01.00
//

#pragma once

#include <string>
#include <vector>

class base64
{
public:
   static void encode(const std::vector<uint8_t>& bytes_to_encode, std::string& encoded_string);
   static void decode(const std::string& encoded_string, std::vector<uint8_t>& decoded_bytes);
};
