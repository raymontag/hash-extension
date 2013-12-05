/**
 * main.c
 *
 * License: MIT
 *
 * Copyright (c) 2013 Karsten-Kai König <kkoenig@posteo.de>
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "sha1.h"
#include "commander.h"

/** Global variables for option parsing:
 *
 * input_string - parsing variable for string to hash
 * orig_string - parsing variable for original string
 * input_length, orig_length - string lengths of both
 * key_length - parsing variable for secret length
 *
 */
const char *input_string, *orig_string;
uint64_t input_length, orig_length;
int key_length;

/** Option flags variable
 *
 * 0b00 = Nothing set
 * 0b01 = orig_string_set
 * 0b10 = new_string_set
 *
 */
uint8_t flags = 0b00;


static void parse_string(command_t *self) {
  /* Parse the string to hash */

  if(self->arg) {
    input_length = strlen(self->arg);
    input_string = self->arg;
  } else {
    input_length = 0;
    input_string = calloc(input_length + 1, sizeof(char));
    input_string = "";
  }

  flags |= 0b10;
}

static void parse_orig_string(command_t *self) {
  /* Parse the original string, e.g. valid massage from server */

  if(self->arg) {
    orig_length = strlen(self->arg);
    orig_string = self->arg;
  } else {
    orig_length = 0;
    orig_string = calloc(orig_length + 1, sizeof(char));
    orig_string = "";
  }

  flags |= 0b01;
}

static void parse_sig(command_t *self) {
  /* Parse the signature of the original string */

  char tmp_sig_buf[8]; // To hold the original signature

  if(strlen(self->arg) != 40) {
    printf("%d", (int) strlen(self->arg));
    printf("A valid MAC consists of 40 hex signs\n");
    exit(1);
  }

  // Slice signature in five 4 byte and copy them to the registers
  memcpy(tmp_sig_buf, &(self->arg[0]), 8 * sizeof(char));
  H0 = (uint32_t) strtol(tmp_sig_buf, NULL, 16);
  memcpy(tmp_sig_buf, &(self->arg[8]), 8 * sizeof(char));
  H1 = (uint32_t) strtol(tmp_sig_buf, NULL, 16);
  memcpy(tmp_sig_buf, &(self->arg[16]), 8 * sizeof(char));
  H2 = (uint32_t) strtol(tmp_sig_buf, NULL, 16);
  memcpy(tmp_sig_buf, &(self->arg[24]), 8 * sizeof(char));
  H3 = (uint32_t) strtol(tmp_sig_buf, NULL, 16);
  memcpy(tmp_sig_buf, &(self->arg[32]), 8 * sizeof(char));
  H4 = (uint32_t) strtol(tmp_sig_buf, NULL, 16);
}

static void parse_length(command_t *self) {
  /* Parse the secret length */

  if(self->arg) {
    key_length = atoi(self->arg);
  } else {
    key_length = 0;
  }

  if(key_length < 0) {
    printf("A positive keylength is needed\n");
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  /** Local variables:
   *
   * input_buffer, orig_buffer - to hold the correspondig parsed strings in n*64 Byte blocks, n integer
   * tmp - SHA1 is processed on 64 Byte blocks, tmp is used to hold them for computation
   * orig_buffer_length, input_buffer_length - hold the buffer length; this is the string length rounded to a
   *                                           multiple of 64 Byte
   * cmd - struct for parsing the options
   */
  char *input_buffer, *orig_buffer, tmp[BLOCKSIZE];
  uint64_t orig_buffer_length, input_buffer_length;
  command_t cmd;

  command_init(&cmd, argv[0], "0.1");
  command_option(&cmd, "-s", "--string [arg]", "the string to hash. default is the empty string", parse_string);
  command_option(&cmd, "-o", "--orig [arg]", "the original string. default is the empty string", parse_orig_string);
  command_option(&cmd, "-S", "--sig <arg>", "the original signature (MAC)", parse_sig);
  command_option(&cmd, "-k", "--keylength [arg]", "the length of the secret key. default is 0", parse_length);
  command_parse(&cmd, argc, argv);

  // If -s wasn't set it is expected that the empty string is parsed
  if(!(flags & 0b10)) {
    input_length = 0;
    input_string = calloc(input_length + 1, sizeof(char));
    input_string = "";
  }

  // If key_length is not provided the default value is 0
  if(!key_length) {
    key_length = 0;
  }

  // Pad the string provided by -s
  if(input_length % BLOCKSIZE < 56) {
    input_buffer_length = (input_length / BLOCKSIZE + 1) * BLOCKSIZE;
  } else {
    input_buffer_length = (input_length / BLOCKSIZE + 2) * BLOCKSIZE;
  }
  input_buffer = calloc(input_buffer_length, sizeof(char));
  strcpy(input_buffer, input_string);
  padMessage(input_buffer, input_buffer_length, 0);
    
  // If -o is provided pad the original string but with keylength included
  if(flags & 0b01) {
    if((orig_length + key_length) % BLOCKSIZE < 56) {
      orig_buffer_length = ((orig_length + key_length) / BLOCKSIZE + 1) * BLOCKSIZE;
    } else {
      orig_buffer_length = ((orig_length + key_length) / BLOCKSIZE + 2) * BLOCKSIZE;
    }
    orig_buffer = calloc(orig_buffer_length, sizeof(char));
    strcpy(orig_buffer, orig_string);
    padMessage(orig_buffer, orig_buffer_length, (uint64_t) key_length);
  }

  // Compute hash for the input string, when indicated with updated registers
  for(uint64_t i = 0; i < input_buffer_length / BLOCKSIZE; i++) {
    memcpy(tmp, &input_buffer[i * BLOCKSIZE], BLOCKSIZE);
    processBlock(tmp);
  }
    
  // Print the result
  if(!(flags & 0b01)) { // No original string provided
    printf("Signature: %08x%08x%08x%08x%08x\n", H0, H1, H2, H3, H4);
  } else {
    printf("New Signature: %08x%08x%08x%08x%08x\n\n", H0, H1, H2, H3, H4);
    printf("What you probably wanna send to a server: \n");
    for(uint64_t  i = 0; i < orig_buffer_length - key_length; i++) {
      printf("%02x", (unsigned char) orig_buffer[i]);
    }
    for(uint64_t i = 0; i < input_length; i++) {
      printf("%02x", (unsigned char) input_buffer[i]);
    }
    printf("\n\n");
    printf("Or with characters: \n");
    for(uint64_t i = 0; i < orig_length; i++) {
      printf("%c", (unsigned char) orig_buffer[i]);
    }
    for(uint64_t i = orig_length; i < orig_buffer_length - key_length; i++) {
      printf("%02x", (unsigned char) orig_buffer[i]);
    }
    for(uint64_t i = 0; i < input_length; i++) {
      printf("%c", (unsigned char) input_buffer[i]);
    }
    printf("\n\n");
  }
}

