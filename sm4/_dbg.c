#include <stdio.h>
#include "sm4.h"
#include "sm4_aesni_avx2.h"
static void hex(const char *t, const uint8_t *p, int n) {
  printf("%s: ", t);
  for (int i = 0; i < n; i++) printf("%02x", p[i]);
  printf("\n");
}
int main(void) {
  static const uint8_t key_pt[16] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
  };
  uint8_t in[64], s[64], a[64];
  sm4_key_t enc;
  int i;
  sm4_setkey_enc(&enc, key_pt);
  for (i = 0; i < 4; i++) memcpy(in + i*16, key_pt, 16);
  memcpy(s, in, 64);
  memcpy(a, in, 64);
  sm4_encrypt_blocks(&enc, s, 4, s);
  sm4_encrypt_blocks_aesni_avx2(&enc, a, 4, a);
  hex("scalar", s, 16);
  hex("aesni ", a, 16);
  return 0;
}
