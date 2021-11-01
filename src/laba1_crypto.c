/*
 ============================================================================
 Name        : laba1_crypto.c
 Author      :
 Version     :
 Copyright   : Your copyright notice
 Description : SP network in C
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

/* Структура данных, в которой хранятся переменные которые используются при
 * шифровании СП сетью*/
struct sp_net_s {
  char user_input[MAX_INPUT_SIZE];  /*User input text string*/
  char sub_blocks[SUB_BLOCKS_SIZE]; /*Block's used in substitution operation*/
  char cyphered_input[MAX_INPUT_SIZE];   /*Array to store the ciphered blocks of
                                            user input*/
  char uncyphered_input[MAX_INPUT_SIZE]; /*Array to store the unciphered blocks
                                          of user input*/

  size_t blocks_len;  /*Длина блоков для шифрования*/
  uint16_t cur_block; /*Текущий блок для шифрования данных СП сетью*/
  uint16_t cur_block_id; /*Номер блока который шифруется в данный момент*/
  uint16_t block_to_p; /*Блок который передается в операцию подстановки*/

  /*Substitutions tables order. Таблицы подстановки, которые используются в
   * блоке шифрования в  порядке их расположения. От 1 до 12.*/
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
  /*Permutations used to cypher. Аналогичный блок таблиц подстановки*/
  uint8_t perm_1[BLOCK_SIZE];
  uint8_t perm_2[BLOCK_SIZE];
  uint8_t perm_3[BLOCK_SIZE];
} sp_net;

#define FIRST_4_BITS 0xFFF0
#define BITMASK_CLEAR(x, mask) ((x) &= (~(mask)))

/* Массивы в которых хранятся таблицы замены. Индекс элемента заменяется на
 * значение элемента в массиве.*/
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

/* Массивы в которых хранятся таблицы подстановки.*/
uint8_t V_perm_table[BLOCK_SIZE] = {5,  3,  12, 9,  1,  8,  4,  6,
                                    11, 16, 2,  15, 14, 10, 13, 7};

uint8_t W_perm_table[BLOCK_SIZE] = {10, 14, 6,  8, 4,  2,  12, 7,
                                    5,  9,  16, 3, 15, 13, 1,  11};

uint8_t X_perm_table[BLOCK_SIZE] = {9,  1, 6, 3,  7, 16, 12, 13,
                                    15, 4, 8, 10, 5, 14, 2,  11};
/* Вспомогательная функция для проверки на наличие ошибок в других функциях. При
 * наличии ошибки производится выход из программы.*/
static inline void check_err(int err) {
  if (err != 0) {
    printf("Error occurred\n");
    exit(EXIT_FAILURE);
  }
}

/* Вспомогательная функция для того, чтобы показать сообщение в шеснадцатиричном
 * виде.*/
static void show_message_hex(char *mes, size_t len) {
  for (size_t var = 0; var < len; ++var) {
    printf("%x", (uint8_t)mes[var]);
  }
  printf("\n");
}

/*Функция предназначенная для получения пользовательского ввода. Сохраняет
 * вводимый пользователем текст в массив данных*/
int get_input(void) {
  int err = 0;

  printf("Please enter the information you want to cipher\n");
  if (NULL == fgets(sp_net.user_input, MAX_INPUT_SIZE, stdin)) {
    printf("Failed to read the input. Maximum input size 80 symbols\n");
    err = -1;
    goto out;
  }

  printf("You've entered: %s \n", sp_net.user_input);
out:
  return err;
}

/* Функция подстановки, параметры ( block - массив данных - 16 бит, subs_table -
 * таблица по которой происходит подстановка*/
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

  *block = subs_table[(int)*block];
out:
  return err;
}
/* Получает на вход массив данных(array) и значение(value), которое храниться в
 * этом массиве, возвращает индекс элемента под которым хранится это значение*/
static uint8_t get_elem_index(uint8_t *array, uint8_t value) {
  for (uint8_t i = 0; i < BLOCK_SIZE; i++) {
    if (value == array[i]) {
      return i;
    }
  }
  return 0;
}

/*Обратная операция замены. На вход получает блок данных(block) и
 * таблицу(subs_table) по которой происходила замена. Значение при обратной
 * операции замены соответсвует индексу элемента под которым стоит текущее
 * значение блока*/
int unsubst(char *block, uint8_t *subs_table) {
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
  *block = get_elem_index(subs_table, (uint8_t)*block);
out:
  return err;
}

/*Вспомогательная операция - возращает значение бита(bit) в блоке(byte) данных.
 * 0 либо 1*/
static inline uint8_t bit_test(uint16_t bit, uint16_t byte) {
  bit = 1 << bit;
  return (bit & byte) ? 1 : 0;
}

/* Операция подстановки. Получает на вход блок данных и таблицу подстановки.
 * После каждый бит становится на место, которое указано для него в таблице
 * подстановки. В таблицах подстановки биты указаны с 1го, а не с 0го индекса*/
int permutation(uint16_t *block, uint8_t *perm_table) {
  int err = 0;
  uint16_t start_block = *block;
  uint16_t out = 0;
  int8_t curr_bit_val = 0;
  uint8_t bit_index = 0;

  if (!block || !perm_table) {
    printf("Error with passed pointers\n");
    err = -1;
    goto out;
  }

  for (int16_t i = 0; i < BLOCK_SIZE; ++i) {
    curr_bit_val = bit_test(i, start_block);
    bit_index = perm_table[i] - 1;
    if (curr_bit_val != 0) {
      out |= (1 << bit_index);
    } else {
      out &= ~(1 << bit_index);
    }
  }
  *block = out;

out:
  return err;
}

/* Обратная операция подстановки. Получает на вход блок данных и таблицу
 * подстановки. В ходе операции берется каждый бит, и возвращается индекс в
 * таблице подстановки, на который этот бит был переставлен. Далеее бит
 * записывается на свое место в котором он был до подстановки. В таблицах
 * подстановки биты указаны с 1го, а не с 0го индекса*/
int unpermutation(uint16_t *block, uint8_t *perm_table) {
  int err = 0;
  uint16_t start_block = *block;
  uint16_t out = 0;
  int8_t curr_bit_val = 0;
  int8_t index_to_write = 0;

  if (!block || !perm_table) {
    printf("Error with passed pointers\n");
    err = -1;
    goto out;
  }

  for (int16_t i = 0; i < BLOCK_SIZE; ++i) {
    curr_bit_val = bit_test(i, start_block);
    index_to_write = get_elem_index(perm_table, i + 1);
    if (curr_bit_val) {
      out |= (1 << index_to_write);
    } else {
      out &= ~(1 << (index_to_write));
    }
  }
  *block = out;
out:
  return err;
}

/* Операция определяет количество блоков в исходном тексте. Для будущего
 * шифрования СП сетью. Если количество байтов не четное(нельзя сформировать
 * полный последний блок, минимальный размер которого 2 байта). Последний байт
 * дополняется символом пробела.*/
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
  sp_net.blocks_len /= 2;
  sp_net.cur_block_id = 0;
  printf("Message entered in hex is :");
  show_message_hex(sp_net.user_input, sp_net.blocks_len);
out:
  return err;
}

/*Операция получения текущего 16-битного блока для последующего его шифрования
 * СП-сетью*/
static inline void get_current_block(void) {
  uint8_t byte_id = sp_net.cur_block_id * BYTES_IN_BLOCK;
  uint8_t first_block_part = sp_net.user_input[byte_id];
  uint8_t second_block_part = sp_net.user_input[++byte_id];
  sp_net.cur_block = (first_block_part << 8) | second_block_part;
  sp_net.cur_block_id++;
}

/*Операция разбиения текущего 16-битного блока на 4х битные блоки для
 * последующего проведения операции замены над каждым из 4х-битных блоков.*/
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

/*Операция восстановление блока в 16-битный формат. Для проведения операции
 * подстановки после замены.*/
static void renew_block_after_s(void) {
  sp_net.cur_block = 0;
  sp_net.cur_block = sp_net.sub_blocks[3];
  sp_net.cur_block |= (sp_net.sub_blocks[2] << 4);
  sp_net.cur_block |= (sp_net.sub_blocks[1] << 8);
  sp_net.cur_block |= (sp_net.sub_blocks[0] << 12);
}

/*Сохранение результата шифрования одного блока после прохождения полного цикла
 * шифрования СП сетью*/
static void save_cyphered_block(void) {
  uint8_t byte_id = (sp_net.cur_block_id - 1) * BYTES_IN_BLOCK;
  sp_net.cyphered_input[byte_id] = sp_net.cur_block >> 8;
  sp_net.cyphered_input[byte_id + 1] = sp_net.cur_block;
}

/*Сохранение результата дешифрования одного блока после прохождения полного
 * цикла дешифрования СП сетью*/
static void save_uncyphered_block(void) {
  uint8_t byte_id = sp_net.cur_block_id * BYTES_IN_BLOCK;
  sp_net.uncyphered_input[byte_id] = sp_net.cur_block >> 8;
  sp_net.uncyphered_input[byte_id + 1] = sp_net.cur_block;
}

/* Функция для проведения полного цикла шифрования исходного текста.*/
int sp_cipher(void) {
  int err = 0;
  // Цикл шифрования. Шифрование происходит циклически, в зависимости от
  // количества блоков.
  for (int i = 0; i < sp_net.blocks_len; i++) {
    // Начало цикла
    get_current_block(); // Получаем текущий блок для шифрования
    get_sub_blocks(); // Разделяем 16-битный блок на 4-бит подблоки для операции
                      // замены

    // Блок операций замены (4 шт)
    subst(&sp_net.sub_blocks[0], sp_net.subs_1);
    subst(&sp_net.sub_blocks[1], sp_net.subs_2);
    subst(&sp_net.sub_blocks[2], sp_net.subs_3);
    subst(&sp_net.sub_blocks[3], sp_net.subs_4);

    // Возобновляем в 16-бит блок после замены
    renew_block_after_s();

    //Проводим операцию подстановки
    permutation(&sp_net.cur_block, sp_net.perm_1);

    // Разделяем 16-битный блок на 4-бит подблоки для операции замены
    get_sub_blocks();

    // Блок операций замены (4 шт)
    subst(&sp_net.sub_blocks[0], sp_net.subs_5);
    subst(&sp_net.sub_blocks[1], sp_net.subs_6);
    subst(&sp_net.sub_blocks[2], sp_net.subs_7);
    subst(&sp_net.sub_blocks[3], sp_net.subs_8);

    // Возобновляем в 16-бит блок после замены
    renew_block_after_s();

    //Проводим операцию подстановки
    permutation(&sp_net.cur_block, sp_net.perm_2);

    // Разделяем 16-битный блок на 4-бит подблоки для операции замены
    get_sub_blocks();

    // Блок операций замены (4 шт)
    subst(&sp_net.sub_blocks[0], sp_net.subs_9);
    subst(&sp_net.sub_blocks[1], sp_net.subs_10);
    subst(&sp_net.sub_blocks[2], sp_net.subs_11);
    subst(&sp_net.sub_blocks[3], sp_net.subs_12);

    // Возобновляем в 16-бит блок после замены
    renew_block_after_s();

    // Проводим операцию подстановки
    permutation(&sp_net.cur_block, sp_net.perm_3);

    // Сохраняем зашифрованный блок
    save_cyphered_block();
    // Конец прохождения цикла
  }

  // Вывод полученного сообщения в итоге шифрования в 16-тиричном виде
  printf("Cyphered messsage in hex: ");
  show_message_hex(sp_net.cyphered_input, sp_net.blocks_len);

  return err;
}

/*Операция для получения текущего блока для дешифрования*/
static void get_current_block_uncipher(void) {
  sp_net.cur_block_id--;
  uint8_t byte_id = sp_net.cur_block_id * BYTES_IN_BLOCK;
  uint8_t first_block_part = sp_net.cyphered_input[byte_id];
  uint8_t second_block_part = sp_net.cyphered_input[++byte_id];
  sp_net.cur_block = (first_block_part << 8) | second_block_part;
}

/* Функция для проведения полного цикла дешифрования закрытого текста. Обратные
 * операции выполняются в обратном порядке относительно шифрования*/
int sp_uncipher(void) {
  int err = 0;

  // Цикл дешифрования. ДеШифрование происходит циклически, в зависимости от
  // количества блоков. Операции в цикле выполняются в обратном порядке
  // относительно шифрования.
  for (int i = 0; i < sp_net.blocks_len; i++) {
    //Начало цикла дешифрования для каждого блока

    // Получение текущего блока для дешифрования
    get_current_block_uncipher();
    //Обратная операция перестановки
    unpermutation(&sp_net.cur_block, sp_net.perm_3);
    // Разделяем 16-битный блок на 4-бит подблоки для операции замены
    get_sub_blocks();
    // Блок обратных операций замены
    unsubst(&sp_net.sub_blocks[0], sp_net.subs_12);
    unsubst(&sp_net.sub_blocks[1], sp_net.subs_11);
    unsubst(&sp_net.sub_blocks[2], sp_net.subs_10);
    unsubst(&sp_net.sub_blocks[3], sp_net.subs_9);
    // Восстановление в 16-бит блок после проведения обратных операций замены
    renew_block_after_s();
    //Обратная операция перестановки
    unpermutation(&sp_net.cur_block, sp_net.perm_2);
    // Разделяем 16-битный блок на 4-бит подблоки для операции замены
    get_sub_blocks();
    // Блок обратных операций замены
    unsubst(&sp_net.sub_blocks[0], sp_net.subs_8);
    unsubst(&sp_net.sub_blocks[1], sp_net.subs_7);
    unsubst(&sp_net.sub_blocks[2], sp_net.subs_6);
    unsubst(&sp_net.sub_blocks[3], sp_net.subs_5);
    // Восстановление в 16-бит блок после проведения обратных операций замены
    renew_block_after_s();
    //Обратная операция перестановки
    unpermutation(&sp_net.cur_block, sp_net.perm_1);
    // Разделяем 16-битный блок на 4-бит подблоки для операции замены
    get_sub_blocks();
    // Блок обратных операций замены
    unsubst(&sp_net.sub_blocks[0], sp_net.subs_4);
    unsubst(&sp_net.sub_blocks[1], sp_net.subs_3);
    unsubst(&sp_net.sub_blocks[2], sp_net.subs_2);
    unsubst(&sp_net.sub_blocks[3], sp_net.subs_1);
    // Восстановление в 16-бит блок после проведения обратных операций замены
    renew_block_after_s();
    // Сохранение дешифрованного блока данных
    save_uncyphered_block();
    // Конец цикла дешифрования одного блока
  }
  // Вывод полученного сообщения в результате дешифрования в символьном виде
  printf("Unciphered messsage :%s\n", sp_net.uncyphered_input);
  // Вывод полученного сообщения в результате дешифрования в шестнадцатиричном
  // виде
  printf("Unciphered messsage in hex: ");
  show_message_hex(sp_net.uncyphered_input, sp_net.blocks_len);

  return err;
}

/*Функция которая используется для задания используемых в ходе шифрования таблиц
 * замены и подстановки*/
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

// Основная функция. Точка входа программы. С нее начинается исполнение всего
// кода.
int main(void) {
  int ret_val = 0; // Переменная для проверки возвращаемых значений функций.
  init_SP_tables(); // Регистрируем таблицы замены и подстановки.
  ret_val = get_input(); // Получаем вводимые пользователем данные.
  check_err(ret_val); // Проверяем корректность исполнения предыдущей функции

  ret_val =
      get_blocks_len(); // Получаем количество блоков для шифрования исходя из
                        // количества введенных пользователем символов
  check_err(ret_val); // Проверяем корректность исполнения предыдущей функции
  sp_cipher(); // Проводим полный цикл шифрования
  sp_uncipher(); // Проводим полный цикл дешифрования

  return EXIT_SUCCESS; // Выходим из программы
}
