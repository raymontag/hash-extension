/**
 * sha1.c
 *
 * License: MIT
 *
 * Copyright (c) 2013 Karsten-Kai König <kkoenig@posteo.de>
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "sha1.h"

// Standard values of the registers as specified by NIST-standard
uint32_t H0 = 0x67452301;
uint32_t H1 = 0xEFCDAB89;
uint32_t H2 = 0x98BADCFE;
uint32_t H3 = 0x10325476;
uint32_t H4 = 0xC3D2E1F0;


void padMessage(char *buffer, uint64_t buffer_length, uint64_t key_length) {
  uint64_t input_length = strlen(buffer);
  buffer[input_length] = 0x80;
  input_length += key_length;

   // If condition is true padding fits in the block which contains the string
  if((input_length + 1) % BLOCKSIZE <= 56) {
    for(uint64_t i = 0; i < 56 - ((input_length + 1) % BLOCKSIZE); i++) {
      buffer[input_length + 1 + i] = 0x00;
    }
  } else { // Else padding has to be continued in a new block
    // Fill second last block with zeros
    for(int i = 0; 1; i++) {
      buffer[input_length + 1 + i] = 0x00;
      if(((input_length + 2 + i)) % BLOCKSIZE == 0)
	break;
    }

    for(int i = BLOCKSIZE; buffer_length - i < buffer_length - 9; i--) {
      buffer[buffer_length - i] = 0x00;
    }
  }

  input_length *= 8; // Number of bits not of bytes is saved!
  buffer[buffer_length - 8 - key_length] = (unsigned char) ((input_length>>56)&0xff); // Big endian
  buffer[buffer_length - 7 - key_length] = (unsigned char) ((input_length>>48)&0xff);
  buffer[buffer_length - 6 - key_length] = (unsigned char) ((input_length>>40)&0xff);
  buffer[buffer_length - 5 - key_length] = (unsigned char) ((input_length>>32)&0xff);
  buffer[buffer_length - 4 - key_length] = (unsigned char) ((input_length>>24)&0xff);
  buffer[buffer_length - 3 - key_length] = (unsigned char) ((input_length>>16)&0xff);
  buffer[buffer_length - 2 - key_length] = (unsigned char) ((input_length>> 8)&0xff);
  buffer[buffer_length - 1 - key_length] = (unsigned char)     ((input_length)&0xff);
}

void processBlock(char block[64]) {
  //Here comes the math-magic
  uint32_t W[80] = { 0 };
  uint32_t A, B, C, D, E, TEMP;

  for(int t = 0; t < 16; t++) {
    W[t] |= (uint32_t)block[t * 4 + 3];
    W[t] |= ((((uint32_t)block[t * 4 + 2])<<8)&0xff00);
    W[t] |= ((((uint32_t)block[t * 4 + 1])<<16)&0xff0000);
    W[t] |= ((((uint32_t)block[t * 4])<<24)&0xff000000);
  }

  for(int t = 16; t < 80; t++) {
    W[t] = cycleWord(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
  }

  A = H0;
  B = H1;
  C = H2;
  D = H3;
  E = H4;

  for(int t = 0; t < 20; t++) {
    TEMP = cycleWord(A, 5) + f0(B, C, D) + E + W[t] + K0;
    E = D;
    D = C;
    C = cycleWord(B, 30);
    B = A;
    A = TEMP;
  }    

  for(int t = 20; t < 40; t++) {
    TEMP = cycleWord(A, 5) + f13(B, C, D) + E + W[t] + K1;
    E = D;
    D = C;
    C = cycleWord(B, 30);
    B = A;
    A = TEMP;
  }    

  for(int t = 40; t < 60; t++) {
    TEMP = cycleWord(A, 5) + f2(B, C, D) + E + W[t] + K2;
    E = D;
    D = C;
    C = cycleWord(B, 30);
    B = A;
    A = TEMP;
  }    

  for(int t = 60; t < 80; t++) {
    TEMP = cycleWord(A, 5) + f13(B, C, D) + E + W[t] + K3;
    E = D;
    D = C;
    C = cycleWord(B, 30);
    B = A;
    A = TEMP;
  }    

  H0 = H0 + A;
  H1 = H1 + B;
  H2 = H2 + C;
  H3 = H3 + D;
  H4 = H4 + E;
}

