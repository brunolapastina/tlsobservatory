#pragma once
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <cassert>
#include <tuple>
#include <random>
#include "rand-blackrock.h"

class IPSpaceSweeper
{
public:
   IPSpaceSweeper() : 
      rand_gen(std::random_device()()),
      rand_blackrock()
   {}

   IPSpaceSweeper(const IPSpaceSweeper& rhs) :
      rand_gen(rhs.rand_gen),
      rand_blackrock(rhs.rand_blackrock),
      m_counter(rhs.m_counter),
      m_total_range_length(rhs.m_total_range_length),
      m_ipSpaceToSweep(rhs.m_ipSpaceToSweep)
   {}

   void add_range(const char* addr, unsigned char mask)
   {
      add_range(inet_addr(addr), mask);
   }

   void add_range(unsigned long ip, unsigned char mask)
   {
      printf("%lu.%lu.%lu.%lu/%u  =>  ", ip & 0x000000FF, (ip & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24, mask);

      if (mask > 32)
      {
         printf("Invalid mask\n");
         return;
      }

      const unsigned long ip_mask = (mask) ? (static_cast<signed long>(0x80000000) >> (mask-1)) : 0;
      ip = ntohl(ip);

      if (ip & ~ip_mask)
      {
         printf("Invalid address for mask\n");
         return;
      }

      unsigned long range_size = (~ip_mask) - 1;
      printf("range_size = %lu\n", range_size);

      m_total_range_length += range_size;

      m_ipSpaceToSweep.emplace_back((ip + 1), (ip + range_size));

      std::sort(m_ipSpaceToSweep.begin(), m_ipSpaceToSweep.end(), [](const range_t& a, const range_t& b) {
            return a.begin < b.begin;
         });

      rand_blackrock = BlackRock(m_total_range_length, rand_gen(), 4);
   }

   IPSpaceSweeper get_slice(size_t num_of_slices, size_t index)
   {
      IPSpaceSweeper slice(*this);

      const size_t slice_size = m_total_range_length / num_of_slices;

      slice.m_counter = index * slice_size;

      if (index < num_of_slices - 1)
      {  // Change the end only if it is not the last slice
         slice.m_total_range_length = slice.m_counter + slice_size;
      }

      printf("Slice %zd of %zd - begin=%u  end=%u\n", index, num_of_slices, slice.m_counter, slice.m_total_range_length);

      return slice;
   }

   bool has_range_finished() const noexcept
   {
      return m_counter >= m_total_range_length;
   }

   unsigned long get_ip() noexcept
   {
      const auto val = rand_blackrock.shuffle(m_counter++);
      const auto ret = range_lookup(static_cast<unsigned long>(val));
      return ret;
   }

   std::tuple<unsigned long, unsigned long> get_stats() const noexcept
   {
      return std::make_tuple(m_counter, m_total_range_length);
   }
   
private:
   struct range_t
   {
      range_t(unsigned long b, unsigned long e) : begin(b), end(e) {}
      unsigned long begin;
      unsigned long end;
   };
   
   std::mt19937_64 rand_gen;
   BlackRock rand_blackrock;
   unsigned long m_counter = 0;
   unsigned long m_total_range_length = 0;
   std::vector<range_t> m_ipSpaceToSweep;

   unsigned long range_lookup(unsigned long index) const noexcept
   {
      for (const auto& it : m_ipSpaceToSweep)
      {
         const unsigned long range_len = it.end - it.begin + 1;
         if (index < range_len)
            return it.begin + index;
         else
            index -= range_len;
      }

      assert(false);
      return 0;
   }
};