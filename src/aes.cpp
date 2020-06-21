#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <cralgo/aes.hpp>

namespace cralgo {

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
void AES_SBOX(uint32_t V[8])
   {
   const uint32_t U0 = V[0];
   const uint32_t U1 = V[1];
   const uint32_t U2 = V[2];
   const uint32_t U3 = V[3];
   const uint32_t U4 = V[4];
   const uint32_t U5 = V[5];
   const uint32_t U6 = V[6];
   const uint32_t U7 = V[7];

   const uint32_t y14 = U3 ^ U5;
   const uint32_t y13 = U0 ^ U6;
   const uint32_t y9 = U0 ^ U3;
   const uint32_t y8 = U0 ^ U5;
   const uint32_t t0 = U1 ^ U2;
   const uint32_t y1 = t0 ^ U7;
   const uint32_t y4 = y1 ^ U3;
   const uint32_t y12 = y13 ^ y14;
   const uint32_t y2 = y1 ^ U0;
   const uint32_t y5 = y1 ^ U6;
   const uint32_t y3 = y5 ^ y8;
   const uint32_t t1 = U4 ^ y12;
   const uint32_t y15 = t1 ^ U5;
   const uint32_t y20 = t1 ^ U1;
   const uint32_t y6 = y15 ^ U7;
   const uint32_t y10 = y15 ^ t0;
   const uint32_t y11 = y20 ^ y9;
   const uint32_t y7 = U7 ^ y11;
   const uint32_t y17 = y10 ^ y11;
   const uint32_t y19 = y10 ^ y8;
   const uint32_t y16 = t0 ^ y11;
   const uint32_t y21 = y13 ^ y16;
   const uint32_t y18 = U0 ^ y16;
   const uint32_t t2 = y12 & y15;
   const uint32_t t3 = y3 & y6;
   const uint32_t t4 = t3 ^ t2;
   const uint32_t t5 = y4 & U7;
   const uint32_t t6 = t5 ^ t2;
   const uint32_t t7 = y13 & y16;
   const uint32_t t8 = y5 & y1;
   const uint32_t t9 = t8 ^ t7;
   const uint32_t t10 = y2 & y7;
   const uint32_t t11 = t10 ^ t7;
   const uint32_t t12 = y9 & y11;
   const uint32_t t13 = y14 & y17;
   const uint32_t t14 = t13 ^ t12;
   const uint32_t t15 = y8 & y10;
   const uint32_t t16 = t15 ^ t12;
   const uint32_t t17 = t4 ^ y20;
   const uint32_t t18 = t6 ^ t16;
   const uint32_t t19 = t9 ^ t14;
   const uint32_t t20 = t11 ^ t16;
   const uint32_t t21 = t17 ^ t14;
   const uint32_t t22 = t18 ^ y19;
   const uint32_t t23 = t19 ^ y21;
   const uint32_t t24 = t20 ^ y18;
   const uint32_t t25 = t21 ^ t22;
   const uint32_t t26 = t21 & t23;
   const uint32_t t27 = t24 ^ t26;
   const uint32_t t28 = t25 & t27;
   const uint32_t t29 = t28 ^ t22;
   const uint32_t t30 = t23 ^ t24;
   const uint32_t t31 = t22 ^ t26;
   const uint32_t t32 = t31 & t30;
   const uint32_t t33 = t32 ^ t24;
   const uint32_t t34 = t23 ^ t33;
   const uint32_t t35 = t27 ^ t33;
   const uint32_t t36 = t24 & t35;
   const uint32_t t37 = t36 ^ t34;
   const uint32_t t38 = t27 ^ t36;
   const uint32_t t39 = t29 & t38;
   const uint32_t t40 = t25 ^ t39;
   const uint32_t t41 = t40 ^ t37;
   const uint32_t t42 = t29 ^ t33;
   const uint32_t t43 = t29 ^ t40;
   const uint32_t t44 = t33 ^ t37;
   const uint32_t t45 = t42 ^ t41;
   const uint32_t z0 = t44 & y15;
   const uint32_t z1 = t37 & y6;
   const uint32_t z2 = t33 & U7;
   const uint32_t z3 = t43 & y16;
   const uint32_t z4 = t40 & y1;
   const uint32_t z5 = t29 & y7;
   const uint32_t z6 = t42 & y11;
   const uint32_t z7 = t45 & y17;
   const uint32_t z8 = t41 & y10;
   const uint32_t z9 = t44 & y12;
   const uint32_t z10 = t37 & y3;
   const uint32_t z11 = t33 & y4;
   const uint32_t z12 = t43 & y13;
   const uint32_t z13 = t40 & y5;
   const uint32_t z14 = t29 & y2;
   const uint32_t z15 = t42 & y9;
   const uint32_t z16 = t45 & y14;
   const uint32_t z17 = t41 & y8;
   const uint32_t tc1 = z15 ^ z16;
   const uint32_t tc2 = z10 ^ tc1;
   const uint32_t tc3 = z9 ^ tc2;
   const uint32_t tc4 = z0 ^ z2;
   const uint32_t tc5 = z1 ^ z0;
   const uint32_t tc6 = z3 ^ z4;
   const uint32_t tc7 = z12 ^ tc4;
   const uint32_t tc8 = z7 ^ tc6;
   const uint32_t tc9 = z8 ^ tc7;
   const uint32_t tc10 = tc8 ^ tc9;
   const uint32_t tc11 = tc6 ^ tc5;
   const uint32_t tc12 = z3 ^ z5;
   const uint32_t tc13 = z13 ^ tc1;
   const uint32_t tc14 = tc4 ^ tc12;
   const uint32_t S3 = tc3 ^ tc11;
   const uint32_t tc16 = z6 ^ tc8;
   const uint32_t tc17 = z14 ^ tc10;
   const uint32_t tc18 = ~tc13 ^ tc14;
   const uint32_t S7 = z12 ^ tc18;
   const uint32_t tc20 = z15 ^ tc16;
   const uint32_t tc21 = tc2 ^ z11;
   const uint32_t S0 = tc3 ^ tc16;
   const uint32_t S6 = tc10 ^ tc18;
   const uint32_t S4 = tc14 ^ S3;
   const uint32_t S1 = ~(S3 ^ tc16);
   const uint32_t tc26 = tc17 ^ tc20;
   const uint32_t S2 = ~(tc26 ^ z17);
   const uint32_t S5 = tc21 ^ tc17;

   V[0] = S0;
   V[1] = S1;
   V[2] = S2;
   V[3] = S3;
   V[4] = S4;
   V[5] = S5;
   V[6] = S6;
   V[7] = S7;
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
void AES_INV_SBOX(uint32_t V[8])
   {
   const uint32_t U0 = V[0];
   const uint32_t U1 = V[1];
   const uint32_t U2 = V[2];
   const uint32_t U3 = V[3];
   const uint32_t U4 = V[4];
   const uint32_t U5 = V[5];
   const uint32_t U6 = V[6];
   const uint32_t U7 = V[7];

   const uint32_t Y0 = U0 ^ U3;
   const uint32_t Y2 = ~(U1 ^ U3);
   const uint32_t Y4 = U0 ^ Y2;
   const uint32_t RTL0 = U6 ^ U7;
   const uint32_t Y1 = Y2 ^ RTL0;
   const uint32_t Y7 = ~(U2 ^ Y1);
   const uint32_t RTL1 = U3 ^ U4;
   const uint32_t Y6 = ~(U7 ^ RTL1);
   const uint32_t Y3 = Y1 ^ RTL1;
   const uint32_t RTL2 = ~(U0 ^ U2);
   const uint32_t Y5 = U5 ^ RTL2;
   const uint32_t sa1 = Y0 ^ Y2;
   const uint32_t sa0 = Y1 ^ Y3;
   const uint32_t sb1 = Y4 ^ Y6;
   const uint32_t sb0 = Y5 ^ Y7;
   const uint32_t ah = Y0 ^ Y1;
   const uint32_t al = Y2 ^ Y3;
   const uint32_t aa = sa0 ^ sa1;
   const uint32_t bh = Y4 ^ Y5;
   const uint32_t bl = Y6 ^ Y7;
   const uint32_t bb = sb0 ^ sb1;
   const uint32_t ab20 = sa0 ^ sb0;
   const uint32_t ab22 = al ^ bl;
   const uint32_t ab23 = Y3 ^ Y7;
   const uint32_t ab21 = sa1 ^ sb1;
   const uint32_t abcd1 = ah & bh;
   const uint32_t rr1 = Y0 & Y4;
   const uint32_t ph11 = ab20 ^ abcd1;
   const uint32_t t01 = Y1 & Y5;
   const uint32_t ph01 = t01 ^ abcd1;
   const uint32_t abcd2 = al & bl;
   const uint32_t r1 = Y2 & Y6;
   const uint32_t pl11 = ab22 ^ abcd2;
   const uint32_t r2 = Y3 & Y7;
   const uint32_t pl01 = r2 ^ abcd2;
   const uint32_t r3 = sa0 & sb0;
   const uint32_t vr1 = aa & bb;
   const uint32_t pr1 = vr1 ^ r3;
   const uint32_t wr1 = sa1 & sb1;
   const uint32_t qr1 = wr1 ^ r3;
   const uint32_t ab0 = ph11 ^ rr1;
   const uint32_t ab1 = ph01 ^ ab21;
   const uint32_t ab2 = pl11 ^ r1;
   const uint32_t ab3 = pl01 ^ qr1;
   const uint32_t cp1 = ab0 ^ pr1;
   const uint32_t cp2 = ab1 ^ qr1;
   const uint32_t cp3 = ab2 ^ pr1;
   const uint32_t cp4 = ab3 ^ ab23;
   const uint32_t tinv1 = cp3 ^ cp4;
   const uint32_t tinv2 = cp3 & cp1;
   const uint32_t tinv3 = cp2 ^ tinv2;
   const uint32_t tinv4 = cp1 ^ cp2;
   const uint32_t tinv5 = cp4 ^ tinv2;
   const uint32_t tinv6 = tinv5 & tinv4;
   const uint32_t tinv7 = tinv3 & tinv1;
   const uint32_t d2 = cp4 ^ tinv7;
   const uint32_t d0 = cp2 ^ tinv6;
   const uint32_t tinv8 = cp1 & cp4;
   const uint32_t tinv9 = tinv4 & tinv8;
   const uint32_t tinv10 = tinv4 ^ tinv2;
   const uint32_t d1 = tinv9 ^ tinv10;
   const uint32_t tinv11 = cp2 & cp3;
   const uint32_t tinv12 = tinv1 & tinv11;
   const uint32_t tinv13 = tinv1 ^ tinv2;
   const uint32_t d3 = tinv12 ^ tinv13;
   const uint32_t sd1 = d1 ^ d3;
   const uint32_t sd0 = d0 ^ d2;
   const uint32_t dl = d0 ^ d1;
   const uint32_t dh = d2 ^ d3;
   const uint32_t dd = sd0 ^ sd1;
   const uint32_t abcd3 = dh & bh;
   const uint32_t rr2 = d3 & Y4;
   const uint32_t t02 = d2 & Y5;
   const uint32_t abcd4 = dl & bl;
   const uint32_t r4 = d1 & Y6;
   const uint32_t r5 = d0 & Y7;
   const uint32_t r6 = sd0 & sb0;
   const uint32_t vr2 = dd & bb;
   const uint32_t wr2 = sd1 & sb1;
   const uint32_t abcd5 = dh & ah;
   const uint32_t r7 = d3 & Y0;
   const uint32_t r8 = d2 & Y1;
   const uint32_t abcd6 = dl & al;
   const uint32_t r9 = d1 & Y2;
   const uint32_t r10 = d0 & Y3;
   const uint32_t r11 = sd0 & sa0;
   const uint32_t vr3 = dd & aa;
   const uint32_t wr3 = sd1 & sa1;
   const uint32_t ph12 = rr2 ^ abcd3;
   const uint32_t ph02 = t02 ^ abcd3;
   const uint32_t pl12 = r4 ^ abcd4;
   const uint32_t pl02 = r5 ^ abcd4;
   const uint32_t pr2 = vr2 ^ r6;
   const uint32_t qr2 = wr2 ^ r6;
   const uint32_t p0 = ph12 ^ pr2;
   const uint32_t p1 = ph02 ^ qr2;
   const uint32_t p2 = pl12 ^ pr2;
   const uint32_t p3 = pl02 ^ qr2;
   const uint32_t ph13 = r7 ^ abcd5;
   const uint32_t ph03 = r8 ^ abcd5;
   const uint32_t pl13 = r9 ^ abcd6;
   const uint32_t pl03 = r10 ^ abcd6;
   const uint32_t pr3 = vr3 ^ r11;
   const uint32_t qr3 = wr3 ^ r11;
   const uint32_t p4 = ph13 ^ pr3;
   const uint32_t S7 = ph03 ^ qr3;
   const uint32_t p6 = pl13 ^ pr3;
   const uint32_t p7 = pl03 ^ qr3;
   const uint32_t S3 = p1 ^ p6;
   const uint32_t S6 = p2 ^ p6;
   const uint32_t S0 = p3 ^ p6;
   const uint32_t X11 = p0 ^ p2;
   const uint32_t S5 = S0 ^ X11;
   const uint32_t X13 = p4 ^ p7;
   const uint32_t X14 = X11 ^ X13;
   const uint32_t S1 = S3 ^ X14;
   const uint32_t X16 = p1 ^ S7;
   const uint32_t S2 = X14 ^ X16;
   const uint32_t X18 = p0 ^ p4;
   const uint32_t X19 = S5 ^ X16;
   const uint32_t S4 = X18 ^ X19;

   V[0] = S0;
   V[1] = S1;
   V[2] = S2;
   V[3] = S3;
   V[4] = S4;
   V[5] = S5;
   V[6] = S6;
   V[7] = S7;
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
inline void bit_transpose(uint32_t B[8])
   {
   swap_bits<uint32_t>(B[1], B[0], 0x55555555, 1);
   swap_bits<uint32_t>(B[3], B[2], 0x55555555, 1);
   swap_bits<uint32_t>(B[5], B[4], 0x55555555, 1);
   swap_bits<uint32_t>(B[7], B[6], 0x55555555, 1);

   swap_bits<uint32_t>(B[2], B[0], 0x33333333, 2);
   swap_bits<uint32_t>(B[3], B[1], 0x33333333, 2);
   swap_bits<uint32_t>(B[6], B[4], 0x33333333, 2);
   swap_bits<uint32_t>(B[7], B[5], 0x33333333, 2);

   swap_bits<uint32_t>(B[4], B[0], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[5], B[1], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[6], B[2], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[7], B[3], 0x0F0F0F0F, 4);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
inline void ks_expand(uint32_t B[8], const uint32_t K[], size_t r)
   {
   /*
   This is bit_transpose of K[r..r+4] || K[r..r+4], we can save some computation
   due to knowing the first and second halves are the same data.
   */
   for(size_t i = 0; i != 4; ++i)
      B[i] = K[r + i];

   swap_bits<uint32_t>(B[1], B[0], 0x55555555, 1);
   swap_bits<uint32_t>(B[3], B[2], 0x55555555, 1);

   swap_bits<uint32_t>(B[2], B[0], 0x33333333, 2);
   swap_bits<uint32_t>(B[3], B[1], 0x33333333, 2);

   B[4] = B[0];
   B[5] = B[1];
   B[6] = B[2];
   B[7] = B[3];

   swap_bits<uint32_t>(B[4], B[0], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[5], B[1], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[6], B[2], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[7], B[3], 0x0F0F0F0F, 4);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
inline void shift_rows(uint32_t B[8])
   {
   // 3 0 1 2 7 4 5 6 10 11 8 9 14 15 12 13 17 18 19 16 21 22 23 20 24 25 26 27 28 29 30 31
#if defined(__LP64__)
   for(size_t i = 0; i != 8; i += 2)
      {
      uint64_t x = (static_cast<uint64_t>(B[i]) << 32) | B[i+1];
      x = bit_permute_step<uint64_t>(x, 0x0022331100223311, 2);
      x = bit_permute_step<uint64_t>(x, 0x0055005500550055, 1);
      B[i] = static_cast<uint32_t>(x >> 32);
      B[i+1] = static_cast<uint32_t>(x);
      }
#else
   for(size_t i = 0; i != 8; ++i)
      {
      uint32_t x = B[i];
      x = bit_permute_step<uint32_t>(x, 0x00223311, 2);
      x = bit_permute_step<uint32_t>(x, 0x00550055, 1);
      B[i] = x;
      }
#endif
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
inline void inv_shift_rows(uint32_t B[8])
   {
   // Inverse of shift_rows, just inverting the steps

#if defined(__LP64__)
   for(size_t i = 0; i != 8; i += 2)
      {
      uint64_t x = (static_cast<uint64_t>(B[i]) << 32) | B[i+1];
      x = bit_permute_step<uint64_t>(x, 0x0055005500550055, 1);
      x = bit_permute_step<uint64_t>(x, 0x0022331100223311, 2);
      B[i] = static_cast<uint32_t>(x >> 32);
      B[i+1] = static_cast<uint32_t>(x);
      }
#else
   for(size_t i = 0; i != 8; ++i)
      {
      uint32_t x = B[i];
      x = bit_permute_step<uint32_t>(x, 0x00550055, 1);
      x = bit_permute_step<uint32_t>(x, 0x00223311, 2);
      B[i] = x;
      }
#endif
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
inline void mix_columns(uint32_t B[8])
   {
   // carry high bits in B[0] to positions in 0x1b == 0b11011
   const uint32_t X2[8] = {
      B[1],
      B[2],
      B[3],
      B[4] ^ B[0],
      B[5] ^ B[0],
      B[6],
      B[7] ^ B[0],
      B[0],
   };

   for(size_t i = 0; i != 8; i++)
      {
      const uint32_t X3 = B[i] ^ X2[i];
      B[i] = X2[i] ^ rotr<8>(B[i]) ^ rotr<16>(B[i]) ^ rotr<24>(X3);
      }
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
void inv_mix_columns(uint32_t B[8])
   {
   /*
   OpenSSL's bsaes implementation credits Jussi Kivilinna with the lovely
   matrix decomposition

   | 0e 0b 0d 09 |   | 02 03 01 01 |   | 05 00 04 00 |
   | 09 0e 0b 0d | = | 01 02 03 01 | x | 00 05 00 04 |
   | 0d 09 0e 0b |   | 01 01 02 03 |   | 04 00 05 00 |
   | 0b 0d 09 0e |   | 03 01 01 02 |   | 00 04 00 05 |

   Notice the first component is simply the MixColumns matrix. So we can
   multiply first by (05,00,04,00) then perform MixColumns to get the equivalent
   of InvMixColumn.
   */
   const uint32_t X4[8] = {
      B[2],
      B[3],
      B[4] ^ B[0],
      B[5] ^ B[0] ^ B[1],
      B[6] ^ B[1],
      B[7] ^ B[0],
      B[0] ^ B[1],
      B[1],
   };

   for(size_t i = 0; i != 8; i++)
      {
      const uint32_t X5 = X4[i] ^ B[i];
      B[i] = X5 ^ rotr<16>(X4[i]);
      }

   mix_columns(B);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
inline constexpr uint8_t xtime(uint8_t s)
   {
   return static_cast<uint8_t>(s << 1) ^ ((s >> 7) * 0x1B);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
inline uint32_t InvMixColumn(uint8_t s1)
   {
   const uint8_t s2 = xtime(s1);
   const uint8_t s4 = xtime(s2);
   const uint8_t s8 = xtime(s4);
   const uint8_t s9 = s8 ^ s1;
   const uint8_t s11 = s9 ^ s2;
   const uint8_t s13 = s9 ^ s4;
   const uint8_t s14 = s8 ^ s4 ^ s2;
   return make_uint32(s14, s9, s13, s11);
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
uint32_t SE_word(uint32_t x)
   {
   uint32_t I[8] = { 0 };

   for(size_t i = 0; i != 8; ++i)
      I[i] = (x >> (7-i)) & 0x01010101;

   AES_SBOX(I);

   x = 0;

   for(size_t i = 0; i != 8; ++i)
      x |= ((I[i] & 0x01010101) << (7-i));

   return x;
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
// [cralgo]: Parameter DK has been replaced by ek_words + ek_size.
void aes_encrypt_n(const uint8_t in[], uint8_t out[],
                   size_t blocks,
                   const uint32_t ek_words[], size_t ek_size)
   {
   assert(ek_size == 44 || ek_size == 52 || ek_size == 60);

   const size_t rounds = (ek_size - 4) / 4;

   uint32_t KS[13*8] = { 0 }; // actual maximum is (rounds - 1) * 8
   for(size_t i = 0; i < rounds - 1; i += 1)
      {
      ks_expand(&KS[8*i], ek_words, 4*i + 4);
      }

   const size_t BLOCK_SIZE = 16;
   const size_t BITSLICED_BLOCKS = 8*sizeof(uint32_t) / BLOCK_SIZE;

   while(blocks > 0)
      {
      const size_t this_loop = std::min(blocks, BITSLICED_BLOCKS);

      uint32_t B[8] = { 0 };

      load_be(B, in, this_loop*4);

      for(size_t i = 0; i != 8; ++i)
         B[i] ^= ek_words[i % 4];

      bit_transpose(B);

      for(size_t r = 0; r != rounds - 1; ++r)
         {
         AES_SBOX(B);
         shift_rows(B);
         mix_columns(B);

         for(size_t i = 0; i != 8; ++i)
            B[i] ^= KS[8*r + i];
         }

      // Final round:
      AES_SBOX(B);
      shift_rows(B);
      bit_transpose(B);

      for(size_t i = 0; i != 8; ++i)
         B[i] ^= ek_words[4*rounds + i % 4];

      copy_out_be(out, this_loop*4*sizeof(uint32_t), B);

      in += this_loop * BLOCK_SIZE;
      out += this_loop * BLOCK_SIZE;
      blocks -= this_loop;
      }
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
// [cralgo]: Parameter DK has been replaced by dk_words + dk_size.
void aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks,
                   const uint32_t dk_words[], size_t dk_size)
   {
   assert(dk_size == 44 || dk_size == 52 || dk_size == 60);

   const size_t rounds = (dk_size - 4) / 4;

   uint32_t KS[13*8] = { 0 }; // actual maximum is (rounds - 1) * 8
   for(size_t i = 0; i < rounds - 1; i += 1)
      {
      ks_expand(&KS[8*i], dk_words, 4*i + 4);
      }

   const size_t BLOCK_SIZE = 16;
   const size_t BITSLICED_BLOCKS = 8*sizeof(uint32_t) / BLOCK_SIZE;

   while(blocks > 0)
      {
      const size_t this_loop = std::min(blocks, BITSLICED_BLOCKS);

      uint32_t B[8] = { 0 };

      load_be(B, in, this_loop*4);

      for(size_t i = 0; i != 8; ++i)
         B[i] ^= dk_words[i % 4];

      bit_transpose(B);

      for(size_t r = 0; r != rounds - 1; ++r)
         {
         AES_INV_SBOX(B);
         inv_shift_rows(B);
         inv_mix_columns(B);

         for(size_t i = 0; i != 8; ++i)
            B[i] ^= KS[8*r + i];
         }

      // Final round:
      AES_INV_SBOX(B);
      inv_shift_rows(B);
      bit_transpose(B);

      for(size_t i = 0; i != 8; ++i)
         B[i] ^= dk_words[4*rounds + i % 4];

      copy_out_be(out, this_loop*4*sizeof(uint32_t), B);

      in += this_loop * BLOCK_SIZE;
      out += this_loop * BLOCK_SIZE;
      blocks -= this_loop;
      }
   }

// [cralgo]: Borrowed from Botan (a5cb4c5c, src/lib/block/aes/aes.cpp).
// [cralgo]: Parameter EK has been replaced by ek_words.
// [cralgo]: Parameter DK has been replaced by dk_words.
void aes_key_schedule(const uint8_t key[], size_t length,
                      uint32_t ek_words[],
                      uint32_t dk_words[],
                      bool bswap_keys)
   {
   static const uint32_t RC[10] = {
      0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
      0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000 };

   const size_t X = length / 4;

   // Can't happen, but make static analyzers happy
   assert(X == 4 || X == 6 || X == 8);

   const size_t rounds = (length / 4) + 6;

   // [cralgo]: We do not resize ek/dk here since they have static sizes.
   //           Instead, we introduce the ek_dk_size variable.
   const size_t ek_dk_size = length + 28;
   assert(ek_dk_size <= 60);

   for(size_t i = 0; i != X; ++i)
      ek_words[i] = load_be<uint32_t>(key, i);

   for(size_t i = X; i < 4*(rounds+1); i += X)
      {
      ek_words[i] = ek_words[i-X] ^ RC[(i-X)/X] ^ rotl<8>(SE_word(ek_words[i-1]));

      for(size_t j = 1; j != X && (i+j) < ek_dk_size; ++j)
         {
         ek_words[i+j] = ek_words[i+j-X];

         if(X == 8 && j == 4)
            ek_words[i+j] ^= SE_word(ek_words[i+j-1]);
         else
            ek_words[i+j] ^= ek_words[i+j-1];
         }
      }

   dk_words[0] = ek_words[4*rounds  ];
   dk_words[1] = ek_words[4*rounds+1];
   dk_words[2] = ek_words[4*rounds+2];
   dk_words[3] = ek_words[4*rounds+3];

   for(size_t i = 4; i != 4*rounds; ++i)
      {
      const uint32_t K = ek_words[4*rounds - 4*(i/4) + (i%4)];
      const uint8_t s0 = get_byte(0, K);
      const uint8_t s1 = get_byte(1, K);
      const uint8_t s2 = get_byte(2, K);
      const uint8_t s3 = get_byte(3, K);

      dk_words[i] = InvMixColumn(s0) ^
         rotr<8>(InvMixColumn(s1)) ^
         rotr<16>(InvMixColumn(s2)) ^
         rotr<24>(InvMixColumn(s3));
      }

   dk_words[4*rounds  ] = ek_words[0];
   dk_words[4*rounds+1] = ek_words[1];
   dk_words[4*rounds+2] = ek_words[2];
   dk_words[4*rounds+3] = ek_words[3];

   if(bswap_keys)
      {
      // HW AES on little endian needs the subkeys to be byte reversed
      for(size_t i = 0; i != ek_dk_size; ++i)
         ek_words[i] = reverse_bytes(ek_words[i]);
      for(size_t i = 0; i != ek_dk_size; ++i)
         dk_words[i] = reverse_bytes(dk_words[i]);
      }
   }

// [cralgo]: Original cralgo function.
void aes256_key_schedule(const uint8_t key[],
		aes_secret_key *ek, aes_secret_key *dk) {
	aes_key_schedule(key, 32, ek->words, dk->words, false);
}

// [cralgo]: Original cralgo function.
void aes256_encrypt(const uint8_t in[], uint8_t out[], size_t blocks,
		aes_secret_key *ek) {
	aes_encrypt_n(in, out, blocks, ek->words, 60);
}

// [cralgo]: Original cralgo function.
void aes256_decrypt(const uint8_t in[], uint8_t out[], size_t blocks,
		aes_secret_key *dk) {
	aes_encrypt_n(in, out, blocks, dk->words, 60);
}

} // namespace cralgo
