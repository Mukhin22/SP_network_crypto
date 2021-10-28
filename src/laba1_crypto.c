/*
 ============================================================================
 Name        : laba1_crypto.c
 Author      : Pylhun_Vlada
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_SIZE 80
#define BLOCK_SIZE 16
#define BYTES_IN_BLOCK 2
#define SUB_BLOCKS_SIZE 4

struct sp_net_s {
  char user_input[MAX_INPUT_SIZE];
  size_t blocks_len;
  uint16_t cur_block;
  uint16_t cur_block_id;
  uint16_t block_to_p;
  char sub_blocks[SUB_BLOCKS_SIZE];
  char cyphered_input[MAX_INPUT_SIZE];
  /*Substitutions tables order*/
  uint8_t subs_1[BLOCK_SIZE];
  uint8_t subs_2[BLOCK_SIZE];
  uint8_t subs_3[BLOCK_SIZE];
  uint8_t subs_4[BLOCK_SIZE];
  uint8_t subs_5[BLOCK_SIZE];
  uint8_t subs_6[BLOCK_SIZE];
  uint8_t subs_7[BLOCK_SIZE];
  uint8_t subs_8[BLOCK_SIZE];
  uint8_t subs_9[BLOCK_SIZE];
  uint8_t subs_10[BLOCK_SIZE];
  uint8_t subs_11[BLOCK_SIZE];
  uint8_t subs_12[BLOCK_SIZE];
  /*Permutations used to cypher*/
  uint8_t perm_1[BLOCK_SIZE];
  uint8_t perm_2[BLOCK_SIZE];
  uint8_t perm_3[BLOCK_SIZE];
} sp_net;

#define FIRST_4_BITS 0xFFF0
#define BITMASK_CLEAR(x, mask) ((x) &= (~(mask)))

uint8_t L_subs_table[BLOCK_SIZE] = {8,  14, 9,  3, 15, 4, 0,  13,
                                    11, 6,  12, 5, 7,  1, 10, 2};

uint8_t F_subs_table[BLOCK_SIZE] = {7,  5,  1, 11, 6, 9,  8,  0,
                                    13, 14, 3, 10, 2, 12, 15, 4};

uint8_t M_subs_table[BLOCK_SIZE] = {6,  10, 5,  11, 9, 0,  8, 7,
                                    13, 12, 15, 1,  3, 14, 2, 4};

uint8_t N_subs_table[BLOCK_SIZE] = {9, 13, 0,  14, 1,  6, 8,  12,
                                    7, 2,  11, 5,  10, 4, 15, 3};

uint8_t P_subs_table[BLOCK_SIZE] = {4,  9, 3, 11, 5, 10, 8,  15,
                                    14, 6, 1, 13, 2, 0,  12, 7};

uint8_t O_subs_table[BLOCK_SIZE] = {2, 8,  3, 11, 0,  7, 13, 12,
                                    9, 10, 6, 1,  15, 5, 4,  14};

uint8_t Q_subs_table[BLOCK_SIZE] = {8, 12, 3, 0, 10, 13, 9,  14,
                                    5, 1,  6, 4, 15, 7,  11, 2};

uint8_t D_subs_table[BLOCK_SIZE] = {6, 9, 7,  12, 15, 10, 1,  3,
                                    8, 0, 11, 2,  14, 5,  13, 4};

uint8_t H_subs_table[BLOCK_SIZE] = {11, 9,  6, 12, 2, 7, 1,  10,
                                    13, 14, 0, 8,  3, 5, 15, 4};

uint8_t I_subs_table[BLOCK_SIZE] = {3, 0,  10, 6,  11, 4, 9, 12,
                                    5, 15, 1,  14, 13, 7, 2, 8};

uint8_t C_subs_table[BLOCK_SIZE] = {14, 7, 5, 10, 11, 8, 0, 3,
                                    13, 6, 1, 15, 12, 4, 2, 9};

uint8_t J_subs_table[BLOCK_SIZE] = {12, 8, 6,  15, 14, 0, 3, 13,
                                    7,  2, 11, 1,  10, 5, 9, 4};

uint8_t V_perm_table[BLOCK_SIZE] = {5,  3,  12, 9,  1,  8,  4,  6,
                                    11, 16, 2,  15, 14, 10, 13, 7};

uint8_t W_perm_table[BLOCK_SIZE] = {10, 14, 6,  8, 4,  2,  12, 7,
                                    5,  9,  16, 3, 15, 13, 1,  11};

uint8_t X_perm_table[BLOCK_SIZE] = {9,  1, 6, 3,  7, 16, 12, 13,
                                    15, 4, 8, 10, 5, 14, 2,  11};

static inline void check_err(int err) {
  if (err != 0) {
    printf("Error occurred\n");
    exit(EXIT_FAILURE);
  }
}

int get_input(void) {
  int err = 0;

  printf("Please enter the information you want to cipher\n");
  if (NULL == fgets(sp_net.user_input, MAX_INPUT_SIZE, stdin)) {
    printf("Failed to read the input\n");
    err = -1;
    goto out;
  }

  printf("You've entered: %s \n", sp_net.user_input);
out:
  return err;
}

int subst(char *block, uint8_t *subs_table) {
  int err = 0;

  if (!block || !subs_table) {
    printf("Error with passed pointers\n");
    err = -1;
    goto out;
  }

  if ((*block > (BLOCK_SIZE - 1)) || (*block < 0)) {
    printf("Wrong block size used\n");
    err = -2;
    goto out;
  }

  *block = L_subs_table[(int)*block];
out:
  return err;
}

static inline uint8_t bit_test(uint8_t bit, uint16_t byte) {
  bit = 1 << bit;
  return (bit & byte);
}

int permutation(uint16_t *block, uint8_t *perm_table) {
  int err = 0;
  uint16_t start_block = *block;
  uint16_t out;
  int8_t curr_bit_val = 0;

  if (!block || !perm_table) {
    printf("Error with passed pointers\n");
    err = -1;
    goto out;
  }

  for (int8_t i = 0; i < BLOCK_SIZE; ++i) {
    curr_bit_val = bit_test(i, start_block);
    if (curr_bit_val) {
      out |= 1 << (perm_table[i] - 1);
    } else {
      out &= ~(1 << (perm_table[i] - 1));
    }
  }
  *block = out;
out:
  return err;
}

int get_blocks_len(void) {
  int err = 0;

  if (!sp_net.user_input) {
    printf("User input not found\n");
    err = -1;
    goto out;
  }

  sp_net.blocks_len = strlen(sp_net.user_input) - 1;

  if (!((sp_net.blocks_len % 2) == 0)) {
    printf("Add one more symbol to get the right block's size\n");
    sp_net.user_input[sp_net.blocks_len] = ' ';
    sp_net.blocks_len++;
  }
  sp_net.cur_block_id = 0;
out:
  return err;
}

static inline void get_current_block(void) {
  uint8_t byte_id = sp_net.cur_block_id * BYTES_IN_BLOCK;
  uint8_t first_block_part = sp_net.user_input[byte_id];
  uint8_t second_block_part = sp_net.user_input[++byte_id];
  sp_net.cur_block |= (first_block_part << 8) | second_block_part;
  sp_net.cur_block_id++;
}

static void get_sub_blocks(void) {
  uint8_t byte = sp_net.cur_block;
  BITMASK_CLEAR(byte, FIRST_4_BITS);
  sp_net.sub_blocks[0] = byte;

  byte = sp_net.cur_block;
  sp_net.sub_blocks[1] = byte >> 4;

  byte = ((sp_net.cur_block) >> 8);
  BITMASK_CLEAR(byte, FIRST_4_BITS);
  sp_net.sub_blocks[2] = byte;

  byte = ((sp_net.cur_block) >> 8);
  sp_net.sub_blocks[3] = byte >> 4;
}

static void renew_block_after_s(void) {
  sp_net.cur_block = 0;
  sp_net.cur_block = sp_net.sub_blocks[3];
  sp_net.cur_block |= (sp_net.sub_blocks[2] << 4);
  sp_net.cur_block |= (sp_net.sub_blocks[1] << 8);
  sp_net.cur_block |= (sp_net.sub_blocks[0] << 12);
}
static void save_cyphered_block(void) {
  uint8_t byte_id = (sp_net.cur_block_id - 1) * BYTES_IN_BLOCK;
  sp_net.cyphered_input[byte_id] = sp_net.cur_block >> 8;
  sp_net.cyphered_input[byte_id + 1] = sp_net.cur_block;
}
int sp_cypher(void) {
  int err = 0;
  for (int i = 0; i < sp_net.blocks_len; i++) {
    get_current_block();
    get_sub_blocks();

    subst(&sp_net.sub_blocks[0], sp_net.subs_1);
    subst(&sp_net.sub_blocks[1], sp_net.subs_2);
    subst(&sp_net.sub_blocks[2], sp_net.subs_3);
    subst(&sp_net.sub_blocks[3], sp_net.subs_4);

    renew_block_after_s();

    permutation(&sp_net.cur_block, sp_net.perm_1);

    get_current_block();
    get_sub_blocks();

    subst(&sp_net.sub_blocks[0], sp_net.subs_5);
    subst(&sp_net.sub_blocks[1], sp_net.subs_6);
    subst(&sp_net.sub_blocks[2], sp_net.subs_7);
    subst(&sp_net.sub_blocks[3], sp_net.subs_8);

    renew_block_after_s();

    permutation(&sp_net.cur_block, sp_net.perm_2);

    get_current_block();
    get_sub_blocks();

    subst(&sp_net.sub_blocks[0], sp_net.subs_9);
    subst(&sp_net.sub_blocks[1], sp_net.subs_10);
    subst(&sp_net.sub_blocks[2], sp_net.subs_11);
    subst(&sp_net.sub_blocks[3], sp_net.subs_12);

    renew_block_after_s();

    permutation(&sp_net.cur_block, sp_net.perm_3);
    save_cyphered_block();
  }
out:
  return err;
}

void init_SP_tables(void) {
  memcpy(sp_net.perm_1, V_perm_table, BLOCK_SIZE);
  memcpy(sp_net.perm_2, W_perm_table, BLOCK_SIZE);
  memcpy(sp_net.perm_3, X_perm_table, BLOCK_SIZE);

  memcpy(sp_net.subs_1, L_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_2, F_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_3, M_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_4, N_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_5, P_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_6, O_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_7, Q_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_8, D_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_9, H_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_10, I_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_11, C_subs_table, BLOCK_SIZE);
  memcpy(sp_net.subs_12, J_subs_table, BLOCK_SIZE);
}

int main(void) {

  int ret_val = 0;
  init_SP_tables();
  ret_val = get_input();
  check_err(ret_val);

  ret_val = get_blocks_len();
  check_err(ret_val);
  sp_cypher();
  //  get_current_block();
  //  get_sub_blocks();

#ifdef TEST
  uint8_t block_to_change = 0;
  subst(&block_to_change, L_subs_table);
  printf("%d\n", block_to_change);

  uint16_t block_to_perm = 0xcccc;
  printf("Before perm: %x\n", block_to_perm);
  permutation(&block_to_perm, V_perm_table);
  printf("After perm: %x\n", block_to_perm);
#endif
  return EXIT_SUCCESS;
}
