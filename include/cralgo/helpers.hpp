#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <algorithm>
#include <utility>

namespace cralgo {

// --------------------------------------------------------------------------------------
// Basic operations on bytes / words.
// --------------------------------------------------------------------------------------

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/loadstor.h).
template<typename T> inline constexpr uint8_t get_byte(size_t byte_num, T input)
   {
   return static_cast<uint8_t>(
      input >> (((~byte_num)&(sizeof(T)-1)) << 3)
      );
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/loadstor.h).
inline constexpr uint32_t make_uint32(uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3)
   {
   return ((static_cast<uint32_t>(i0) << 24) |
           (static_cast<uint32_t>(i1) << 16) |
           (static_cast<uint32_t>(i2) <<  8) |
           (static_cast<uint32_t>(i3)));
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/bswap.h).
inline uint16_t reverse_bytes(uint16_t val)
   {
   // [cralgo]: Modified to always assume GCC.
   return __builtin_bswap16(val);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/bswap.h).
inline uint32_t reverse_bytes(uint32_t val)
   {
   // [cralgo]: Modified to always assume GCC.
   return __builtin_bswap32(val);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/bswap.h).
inline uint64_t reverse_bytes(uint64_t val)
   {
   // [cralgo]: Modified to always assume GCC.
   return __builtin_bswap64(val);
   }

// --------------------------------------------------------------------------------------
// Single word endianness utilities.
// --------------------------------------------------------------------------------------

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/loadstor.h).
inline void store_be(uint32_t in, uint8_t out[4])
   {
   // [cralgo]: Discarded optimization.
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/loadstor.h).
inline void store_be(uint64_t in, uint8_t out[8])
   {
   // [cralgo]: Discarded optimization.
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
   out[4] = get_byte(4, in);
   out[5] = get_byte(5, in);
   out[6] = get_byte(6, in);
   out[7] = get_byte(7, in);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/loadstor.h).
template<typename T>
inline T load_be(const uint8_t in[], size_t off)
   {
   in += off * sizeof(T);
   T out = 0;
   for(size_t i = 0; i != sizeof(T); ++i)
      out = static_cast<T>((out << 8) | in[i]);
   return out;
   }

// --------------------------------------------------------------------------------------
// Endianness utilities on arrays of words.
// --------------------------------------------------------------------------------------

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/loadstor.h).
template<typename T>
inline void load_be(T out[],
                    const uint8_t in[],
                    size_t count)
   {
   if(count > 0)
      {
      // [Mangarm]: Discard optimizations for simplicity.
      for(size_t i = 0; i != count; ++i)
         out[i] = load_be<T>(in, i);
      }
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/loadstor.h).
template<typename T>
void copy_out_be(uint8_t out[], size_t out_bytes, const T in[])
   {
   while(out_bytes >= sizeof(T))
      {
      store_be(in[0], out);
      out += sizeof(T);
      out_bytes -= sizeof(T);
      in += 1;
   }

   for(size_t i = 0; i != out_bytes; ++i)
      out[i] = get_byte(i%8, in[0]);
   }

// --------------------------------------------------------------------------------------
// Bit permutations and rotations.
// --------------------------------------------------------------------------------------

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/bit_ops.h).
template<typename T>
inline T bit_permute_step(T x, T mask, size_t shift)
   {
   /*
   See https://reflectionsonsecurity.wordpress.com/2014/05/11/efficient-bit-permutation-using-delta-swaps/
   and http://programming.sirrida.de/bit_perm.html
   */
   const T swap = ((x >> shift) ^ x) & mask;
   return (x ^ swap) ^ (swap << shift);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/bit_ops.h).
template<typename T>
inline void swap_bits(T& x, T& y, T mask, size_t shift)
   {
   const T swap = ((x >> shift) ^ y) & mask;
   x ^= swap << shift;
   y ^= swap;
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/rotr.h).
template<size_t ROT, typename T>
inline constexpr T rotl(T input)
   {
   static_assert(ROT > 0 && ROT < 8*sizeof(T), "Invalid rotation constant");
   return static_cast<T>((input << ROT) | (input >> (8*sizeof(T) - ROT)));
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/utils/rotr.h).
template<size_t ROT, typename T>
inline constexpr T rotr(T input)
   {
   static_assert(ROT > 0 && ROT < 8*sizeof(T), "Invalid rotation constant");
   return static_cast<T>((input >> ROT) | (input << (8*sizeof(T) - ROT)));
   }

// --------------------------------------------------------------------------------------
// Memory cleaning.
// --------------------------------------------------------------------------------------

// [cralgo]: Original cralgo implementation.
// Botan has a function of the same name.
inline void secure_scrub_memory(void *ptr, size_t size) {
	memset(ptr, 0, size);
	asm volatile ("" : : "r"(ptr) : "memory");
}

} // namespace cralgo
