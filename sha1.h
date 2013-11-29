#define cycleWord(a, n) \
((((a) << (n))&0xFFFFFFFF) | ((a) >> (32 - n)))

#define f0(B, C, D) \
((B & C) | ((~B) & D))

#define f13(B, C, D) \
(B ^ C ^ D)

#define f2(B, C, D)\
((B & C) | (B & D) | (C & D))

#define BLOCKSIZE 64

#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6


extern uint32_t H0;
extern uint32_t H1;
extern uint32_t H2;
extern uint32_t H3;
extern uint32_t H4;


void padMessage(char *buf, uint64_t buflen, uint64_t key_length);
void processBlock(char block[64]);

