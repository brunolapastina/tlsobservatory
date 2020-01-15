#pragma once

#include <cstdint>
#include <functional>
#include <algorithm>
#include <string>
#include <stdexcept>

union SHA256Hash
{
   uint8_t	packed8[32]{ 0 };
   uint32_t	packed32[8];
   uint64_t packed64[4];

   SHA256Hash() = default;

   SHA256Hash(const std::string& str)
   {
      if (str.size() != 64)
      {
         throw std::length_error("Invalid SHA256 length");
      }

      auto from_char = [](const char c1, const char c2) -> unsigned char
      {
         auto char_to_uchar = [](const char c1)
         {
            if (('0' <= c1) && (c1 <= '9'))    return c1 - '0';
            else if (('A' <= c1) && (c1 <= 'F'))    return c1 - 'A' + 10;
            else if (('a' <= c1) && (c1 <= 'f'))    return c1 - 'a' + 10;
            else throw std::out_of_range("[SHA256Hash] Invalid character found");
         };
         return (char_to_uchar(c1) << 4) | char_to_uchar(c2);
      };

      for (size_t i = 0; i < 32; ++i)
      {
         this->packed8[i] = from_char(str[2 * i], str[(2 * i) + 1]);
      }
   }

   bool operator==(const SHA256Hash& rhs) const noexcept
   {
      return (this->packed64[0] == rhs.packed64[0]) && (this->packed64[1] == rhs.packed64[1]) &&
             (this->packed64[2] == rhs.packed64[2]) && (this->packed64[3] == rhs.packed64[3]);
   }

   std::string to_string() const
   {
      auto to_char = [](const unsigned char ch) -> char
      {
         if (ch < 10)   return ch + '0';
         else           return ch + 'A' - 10;
      };

      std::string str;
      str.reserve(64);
      std::for_each(this->packed8, this->packed8 + 32, [&](const auto& ch)
      {
         str.push_back(to_char((ch >> 4) & 0x0F));
         str.push_back(to_char( ch       & 0x0F));
      });
      return str;
   }
};


// Inject custom specialization of std::hash in namespace std
namespace std
{
   template<> struct hash<SHA256Hash>
   {
      typedef SHA256Hash argument_type;
      typedef std::size_t result_type;
      result_type operator()(argument_type const& h) const noexcept
      {
         if constexpr (sizeof(result_type) == sizeof(uint64_t))
         {
            return (h.packed64[0] ^ h.packed64[1] ^ h.packed64[2] ^ h.packed64[3]);
         }
         else
         {
            return (h.packed32[0] ^ h.packed32[1] ^ h.packed32[2] ^ h.packed32[3] ^
               h.packed32[4] ^ h.packed32[5] ^ h.packed32[6] ^ h.packed32[7]);
         }
      }
   };
}

class SHA256
{
public:
   SHA256() noexcept = default;

   void update(const unsigned char *input, size_t ilen) noexcept;
   SHA256Hash finish() noexcept;

   static SHA256Hash hash(const unsigned char* data, const size_t len) noexcept
   {
      SHA256 alg;
      alg.update(data, len);
      return alg.finish();
   }

private:
	uint32_t total_[2]{0, 0};			/*!< The number of Bytes processed.  */
	uint32_t state_[8]					/*!< The intermediate digest state.  */
	{
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
		0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
	};
   unsigned char buffer_[64]{};     /*!< The data block being processed. */

	void process( const unsigned char* data ) noexcept;
};