/**
 * sha1.h
 *
 * License: MIT
 *
 * Copyright (c) 2013 Karsten-Kai König <kkoenig@posteo.de>
 */

// Definitions of the functions specified in the NIST-standard
#define cycleWord(a, n) \
((((a) << (n))&0xFFFFFFFF) | ((a) >> (32 - n)))

#define f0(B, C, D) \
((B & C) | ((~B) & D))

#define f13(B, C, D) \
(B ^ C ^ D)

#define f2(B, C, D)\
((B & C) | (B & D) | (C & D))

// Definitions of the variables specified in the NIST-standard
#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

// SHA1-blocksize is 64 Byte
#define BLOCKSIZE 64

// Global variables for the registers
extern uint32_t H0;
extern uint32_t H1;
extern uint32_t H2;
extern uint32_t H3;
extern uint32_t H4;


/** To pad a string
 * 
 * Return value: void - operates per reference
 *
 * @*buf - the buffer to pad
 * @*buflen - length of buffer
 * @*key_length - length of secret
 *
 */
void padMessage(char *buf, uint64_t buflen, uint64_t key_length);

/** Process a single block
 *
 * Return value: void - just updates the global registers H0-4
 *
 * @block - the block to process
 *
 */
void processBlock(char block[BLOCKSIZE]);

