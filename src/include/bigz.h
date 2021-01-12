/* 
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef _BIGZ_H
#define _BIGZ_H

#include <stdint.h>

#include "types.h"
#include "big.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * @fn bigz_t bigz_init(void)
 * @brief Initializes a big integer number.
 * 
 * @return An initialized big integer number, or NULL if error.
 */
bigz_t bigz_init(void);

/** 
 * @fn bigz_t bigz_init_set(bigz_t op)
 * @brief Initializes a big integer number and sets its value to <i>op</i>.
 *
 * @param[in] op The value to use for setting the newly initialized big integer.
 * 
 * @return The initialized and set big integer, or NULL if error.
 */
bigz_t bigz_init_set(bigz_t op);

/** 
 * @fn bigz_t bigz_init_set_ui(unsigned long int op)
 * @brief Initializes and sets a new big integer number to the value in <i>op</i>.
 *
 * @param[in] op The value to use for setting the new big integer.
 * 
 * @return The newly initialized and set big integer, or NULL if error.
 */
bigz_t bigz_init_set_ui(unsigned long int op);

/** 
 * @fn int bigz_free(bigz_t op)
 * @brief Frees the memory allocated for the given big integer number.
 *
 * @param[in,out] op The big integer number to free.
 * 
 * @return IOK or IERROR.
 */
int bigz_free(bigz_t op);

/** 
 * @fn int bigz_set(bigz_t rop, bigz_t op)
 * @brief Sets <i>rop</i> to the value in <i>op</i>.
 *
 * @param[in,out] rop Will be set to the value in <i>op</i>. Must have been
 *  initialized by the caller.
 * @param[in] op The big integer to use for setting <i>rop</i>.
 * 
 * @return IOK or IERROR.
 */
int bigz_set(bigz_t rop, bigz_t op);

/** 
 * @fn int bigz_set(bigz_t rop, bigz_t op)
 * @brief Sets <i>rop</i> to the value in <i>op</i>.
 *
 * @param[in,out] rop Will be set to the value in <i>op</i>. Must have been
 *  initialized by the caller.
 * @param[in] op The unsigned long integer to use for setting <i>rop</i>.
 * 
 * @return IOK or IERROR.
 */
int bigz_set_ui(bigz_t rop, unsigned long int op);

/** 
 * @fn int bigz_set_f(bigz_t rop, bigz_t op)
 * @brief Sets <i>rop</i> to the truncated value of <i>op</i>.
 *
 * @param[in,out] rop Will be set to the value in <i>op</i>. Must have been
 *  initialized by the caller.
 * @param[in] op The big float number to use for setting <i>rop</i>.
 * 
 * @return IOK or IERROR.
 */
//int bigz_set_f(bigz_t z, bigf_t f);

/** 
 * @fn int bigz_sgn(bigz_t op)
 * @brief Returns +1 if <i>op</i> > 0, 0 if <i>op</i> = 0, -1 if <i>op</i> < 0.
 *
 * @param[in] op The operand.
 * 
 * @return +1 if <i>op</i> > 0, 0 if <i>op</i> = 0, -1 if <i>op</i> < 0. If an
 *  error occurs, errno is consequently set.
 */
int bigz_sgn(bigz_t op);

/** 
 * @fn int bigz_cmp(bigz_t op1, bigz_t op2)
 * @brief Returns a number less than, equal to, or greater than 0 if <i>op1</i>
 *  is less than, equal to, or greater than 0.
 *
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand.
 * 
 * @return An integer less than, equal to, or greater than 0 if <i>op1</i>
 *  is less than, equal to, or greater than 0. If an error occurs, errno is
 *  consequently set.
 */
int bigz_cmp(bigz_t op1, bigz_t op2);

/** 
 * @fn int bigz_cmp(bigz_t op1, bigz_t op2)
 * @brief Returns a number less than, equal to, or greater than 0 if <i>op1</i>
 *  is less than, equal to, or greater than 0.
 *
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand.
 * 
 * @return An integer less than, equal to, or greater than 0 if <i>op1</i>
 *  is less than, equal to, or greater than 0. If an error occurs, errno is
 *  consequently set.
 */
int bigz_cmp_ui(bigz_t op1, unsigned long int op2);

/** 
 * @fn int bigz_neg(bigz_t rop, bigz_t op)
 * @brief Sets <i>rop</i> to -1*<i>op</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] op The origin operand.
 * 
 * @return IOK or IERROR.
 */
int bigz_neg(bigz_t rop, bigz_t op);

/** 
 * @fn int bigz_add(bigz_t rop, bigz_t op1, bigz_t op2)
 * @brief Sets <i>rop</i> to <i>op1</i>+<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand.
 * 
 * @return IOK or IERROR.
 */
int bigz_add(bigz_t rop, bigz_t op1, bigz_t op2);

/** 
 * @fn int bigz_add_ui(bigz_t rop, bigz_t op1, bigz_t op2)
 * @brief Sets <i>rop</i> to <i>op1</i>+<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand, an unsigned long integer.
 * 
 * @return IOK or IERROR.
 */
int bigz_add_ui(bigz_t rop, bigz_t op1, unsigned long int op2);

/** 
 * @fn int bigz_sub(bigz_t rop, bigz_t op1, bigz_t op2)
 * @brief Sets <i>rop</i> to <i>op1</i> - <i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand.
 * 
 * @return IOK or IERROR.
 */
int bigz_sub(bigz_t rop, bigz_t op1, bigz_t op2);

/** 
 * @fn int bigz_sub_ui(bigz_t rop, bigz_t op1, bigz_t op2)
 * @brief Sets <i>rop</i> to <i>op1</i> - <i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand, an unsigned long integer.
 * 
 * @return IOK or IERROR.
 */
int bigz_sub_ui(bigz_t rop, bigz_t op1, unsigned long int op2);

/** 
 * @fn int bigz_mul(bigz_t rop, bigz_t op1, bigz_t op2)
 * @brief Sets <i>rop</i> to <i>op1</i>*<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand.
 * 
 * @return IOK or IERROR.
 */
int bigz_mul(bigz_t rop, bigz_t op1, bigz_t op2);

/** 
 * @fn int bigz_mul(bigz_t rop, bigz_t op1, bigz_t op2)
 * @brief Sets <i>rop</i> to <i>op1</i>*<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand, an unsigned long integer.
 * 
 * @return IOK or IERROR.
 */
int bigz_mul_ui(bigz_t rop, bigz_t op1, unsigned long int op2);

/** 
 * @fn int bigz_tdiv(bigz_t q, bigz_t r, bigz_t D, bigz_t d)
 * @brief Divides <i>D</i> by <i>d</i>, storing the quotient in <i>q</i> and the
 *  remainder in <i>r</i>.
 *
 * If either the quotient or the remainder are NULL, they won't be calculated.
 * However, at least one of them must not be NULL.
 *
 * @param[in,out] q Will be set to the obtained quotient. Must have been initialized
 *  by the caller.
 * @param[in,out] r Will be set to the obtained remainder. Must have been initialized
 *  by the caller.
 * @param[in] D The dividend.
 * @param[in] d The divisor.
 * 
 * @return IOK or IERROR.
 */
int bigz_tdiv(bigz_t q, bigz_t r, bigz_t D, bigz_t d);

/** 
 * @fn int bigz_tdiv_ui(bigz_t q, bigz_t r, bigz_t D, bigz_t d)
 * @brief Divides <i>D</i> by <i>d</i>, storing the quotient in <i>q</i> and the
 *  remainder in <i>r</i>.
 *
 * If either the quotient or the remainder are NULL, they won't be calculated.
 * However, at least one of them must not be NULL.
 *
 * @param[in,out] q Will be set to the obtained quotient. Must have been initialized
 *  by the caller.
 * @param[in,out] r Will be set to the obtained remainder. Must have been initialized
 *  by the caller.
 * @param[in] D The dividend.
 * @param[in] d The divisor. An unsigned integer.
 * 
 * @return IOK or IERROR.
 */
int bigz_tdiv_ui(bigz_t q, bigz_t r, bigz_t D, unsigned long int d);

/** 
 * @fn int bigz_divisible_p(bigz_t n, bigz_t d)
 * @brief Returns non-zero if <i>n</i> is divisible by <i>d</i>, or 0 otherwise.
 *
 * @param[in] n The dividend.
 * @param[in] d The divisor.
 * 
 * @return Non-zero if <i>n</i> is divisible by <i>d</i>, or 0 otherwise. If an
 *  error occurs, errno will be set.
 */
int bigz_divisible_p(bigz_t n, bigz_t d);

/** 
 * @fn int bigz_divexact(bigz_t rop, bigz_t n, bigz_t d)
 * @brief When <i>n</i> is known to be divisible by <i>d</i>.
 *
 *  This function stores the result in <i>rop</i>. This routine is much faster 
 *  than a normal division.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] n The dividend.
 * @param[in] d The divisor.
 * 
 * @return IOK or IERROR.
 */
int bigz_divexact(bigz_t rop, bigz_t n, bigz_t d);

/** 
 * @fn int bigz_divexact_ui(bigz_t rop, bigz_t n, bigz_t d)
 * @brief When <i>n</i> is known to be divisible by <i>d</i>.
 *
 *  This function stores the result in <i>rop</i>. This routine is much faster 
 *  than a normal division.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] n The dividend.
 * @param[in] d The divisor.
 * 
 * @return IOK or IERROR.
 */
int bigz_divexact_ui(bigz_t rop, bigz_t n, unsigned long int d);

/** 
 * @fn int bigz_mod(bigz_t rop, bigz_t op, bigz_t mod)
 * @brief Sets <i>rop</i> to the result of <i>op</i> % <i>mod</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] op The first operand.
 * @param[in] mod The modulus.
 * 
 * @return IOK or IERROR.
 */
int bigz_mod(bigz_t rop, bigz_t op, bigz_t mod);

/** 
 * @fn int bigz_powm(bigz_t rop, bigz_t base, bigz_t exp, bigz_t mod)
 * @brief Sets <i>rop</i> to the result of <i>base</i>^<i>exp</i> % <i>mod</i>.
 *
 * @param[in,out] rop Will be set to the obtained result. Must have been
 *  initialized by the caller.
 * @param[in] base The base.
 * @param[in] exp The exponent.
 * @param[in] mod The modulus.
 * 
 * @return IOK or IERROR.
 */
int bigz_powm(bigz_t rop, bigz_t base, bigz_t exp, bigz_t mod);

/** 
 * @fn int bigz_pow_ui(bigz_t rop, bigz_t base, unsigned long int exp)
 * @brief Sets <i>rop</i> to the result of <i>base</i>^<i>exp</i>.
 *
 * @param[in,out] rop Will be set to the obtained result. Must have been
 *  initialized by the caller.
 * @param[in] base The base.
 * @param[in] exp The exponent.
 * 
 * @return IOK or IERROR.
 */
int bigz_pow_ui(bigz_t rop, bigz_t base, unsigned long int exp);

/** 
 * @fn int bigz_ui_pow_ui(bigz_t rop, unsigned long int base, unsigned long int  exp)
 * @brief Sets <i>rop</i> to the result of <i>base</i>^<i>exp</i>.
 *
 * @param[in,out] rop Will be set to the obtained result. Must have been
 *  initialized by the caller.
 * @param[in] base The base.
 * @param[in] exp The exponent.
 * 
 * @return IOK or IERROR.
 */
int bigz_ui_pow_ui(bigz_t rop, unsigned long int base, unsigned long int exp);

/** 
 * @fn int bigz_invert(bigz_t rop, bigz_t op, bigz_t mod)
 * @brief Sets <i>rop</i> to the inverse of <i>op</i> % <i>mod</i>.
 *
 * @param[in,out] rop Will be set to the result of the operation. It must have
 *  been initialized by the caller.
 * @param[in] op The operand.
 * @param[in] mod The modulus.
 * 
 * @return IOK or IERROR.
 */
int bigz_invert(bigz_t rop, bigz_t op, bigz_t mod);

/** 
 * @fn int bigz_probab_prime_p(bigz_t n, int reps)
 * @brief Determines if <i>n</i> is a prime.
 *
 *
 * @param[in] n The number to test.
 * @param[in] reps Controls how many tests are performed. A higher number implies
 *  less probability to return "prime" when <i>n</i> is indeed composite.
 *  According to GMP, 25 is a reasonable number.
 * 
 * @return Return 2 if n is definitely prime, return 1 if n is probably prime 
 *  (without being certain), or return 0 if n is definitely composite. If an
 *  error occurs, errno is set appropriately.
 * NOTE: The current implementation is based on BIGNUM, which only makes 
 * probabilistic claims (i.e., this function will never return 2 at present.)
 * 
 */
int bigz_probab_prime_p(bigz_t n, int reps);

/** 
 * @fn int bigz_nextprime(bigz_t rop, bigz_t lower)
 * @brief Returns the least prime greater than <i>lower</i>.
 *
 * @param[in,out] rop Will be set to the least prime greater than <i>lower</i>.
 *  must have been initialized by the caller.
 * @param[in] lower The lower limit.
 * 
 * @return IOK or IERROR.
 */
int bigz_nextprime(bigz_t rop, bigz_t lower);

/** 
 * @fn int bigz_gcd(bigz_t rop, bigz_t op1, bigz_t op2)
 * @brief Sets <i>rop</i> to the Greatest Common Divisor of <i>op1</i> and
 *  <i>op2</i>.
 *
 * @param[in,out] rop Will be set to the obtained GCD. Must have been initialized
 *  by the caller.
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand.
 * 
 * @return IOK or IERROR.
 */
int bigz_gcd(bigz_t rop, bigz_t op1, bigz_t op2);

/**
 * @fn void bigz_randinit_default(bigz_randstate_t rand)
 * @brief Initializes the random state using default algorithms. See the documentation
 *  of the function gmp_randinit from GMP for further details.
 *
 * @param[in,out] rand The random state variable to initialize.
 */
/* void bigz_randinit_default(bigz_randstate_t rand); */

/** 
 * @fn void bigz_randclear(bigz_randstate_t rand)
 * @brief Frees all memory allocated for <i>rand</i>.
 *
 * @param[in,out] rand The variable to free.
 */
/* void bigz_randclear(bigz_randstate_t rand); */

/** 
 * @fn void bigz_randseed_ui(bigz_randstate_t rand, unsigned long int seed)
 * @brief Seeds the random state variable with the given seed.
 *
 * @param[in,out] rand The random state variable to seed.
 * @param[in] seed The seed to use.
 */
/* void bigz_randseed_ui(bigz_randstate_t rand, unsigned long int seed); */
  
/** 
 * @fn int bigz_urandomm(bigz_t rop, bigz_t n)
 * @brief Generates a uniform random integer within the interval [0,n-1].
 *
 * @param[in,out] rop Will be set to the produced integer. Must have been
 *  initialized by the caller.
 * @param[in] n The upper limit).
 * 
 * @return IOK or IERROR.
 */
int bigz_urandomm(bigz_t rop, bigz_t n);

/** 
 * @fn int bigz_urandomb(bigz_t rop, unsigned long int n)
 * @brief Generates a random integer in the interval [0,2^n-1].
 *
 * @param[in,out] rop Will be set to the produced integer. Must have been
 *  initialized by the caler.
 * @param[in] n The exponent of the upper limit.
 * 
 * @return IOK or IERROR.
 */
int bigz_urandomb(bigz_t rop, unsigned long int n);

/** 
 * @fn size_t bigz_sizeinbits(bigz_t op)
 * @brief Returns the size, in bits, of <i>op</i>.
 *
 * @param[in] op The big number.
 * 
 * @return The number of bits for representing <i>op</i>.
 *  If an error occurs, errno will be set appropriately.
 */
size_t bigz_sizeinbits(bigz_t op);

/** 
 * @fn char* bigz_get_str16(bigz_t op)
 * @brief Returns an hex string representation of <i>op</i>.
 *
 * @param[in] op The big integer.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* bigz_get_str16(bigz_t op);

/** 
 * @fn int bigz_set_str(bigz_t rop, char *str)
 * @brief Sets <i>rop</i> to the number in the hex string <i>str</i>.
 *
 * @param[in,out] rop Will be set to the number imported from <i>str</i>.
 * @param[in] str The string representation of the number.
 * 
 * @return IOK or IERROR.
 */
int bigz_set_str16(bigz_t rop, char *str);

/** 
 * @fn char* bigz_get_str10(bigz_t op)
 * @brief Returns a decimal string representation of <i>op</i>.
 *
 * @param[in] op The big integer.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* bigz_get_str10(bigz_t op);

/** 
 * @fn int bigz_set_str10(bigz_t rop, char *str)
 * @brief Sets <i>rop</i> to the number in the decimal string <i>str</i>.
 *
 * @param[in,out] rop Will be set to the number imported from <i>str</i>.
 * @param[in] str The string representation of the number.
 * 
 * @return IOK or IERROR.
 */
int bigz_set_str10(bigz_t rop, char *str); 

/** 
 * @fn byte_t* bigz_export(bigz_t op, size_t *length)
 * @brief Returns a byte array with the big endian representation of op,
 *  and sets length to the number of bytes of the produced array.
 *
 * @param[in] op The big number to export.
 * @param[in,out] length The length in bytes of the resulting byte array.
 * 
 * @return The resulting byte array or NULL if error.
 */
byte_t* bigz_export(bigz_t op, size_t *length);

/**
 * @fn bigz_t bigz_import(byte_t *bytearray, size_t length)
 * @brief The "inverse" operation of bigz_export.
 *
 * @param[in] bytearray The bytearray from which the bigz will be read.
 * @param[in] length The length of the bytearray, in bytes.
 * 
 * @return A bigz_t object with the imported bigz_t or NULL if error.
 */
bigz_t bigz_import(byte_t *bytearray, size_t length);

/** 
 * @fn int bigz_dump_element_fd(element_t e, FILE *fd)
 * @brief Dumps a bigz <i>e</i> into the specified file descriptor (at its
 *  current position) as binary data.
 *
 * Dumps the bigz into the current position of the received file descriptor
 * prepending them by an int indicating the number of bytes of the element.
 *
 * @param[in] e The bigz to dump.
 * @param[in] fd The file descriptor.
 *
 * @return IOK or IERROR.
 */
int bigz_dump_bigz_fd(bigz_t z, FILE* fd);

/** 
 * @fn bigz_t bigz_get_element_fd(FILE *fd)
 * @brief Gets the bigz stored at the current position of the specified
 *  file descriptor.
 *
 * Reads the number of bytes the bigz occupies (contained in an int field)
 * and then reads exactly the same amount of bytes and loads them into an
 * element.
 *
 * @param[in] fd The file descriptor.
 *
 * @return The read element, or NULL if error.
 */
bigz_t bigz_get_bigz_fd(FILE *fd);

/** 
 * @fn int bigz_clrbit(bigz_t op, unsigned long int index)
 * @brief Sets to 0 the bit at the specified position of <i>op</i>.
 *
 * @param[in,out] op The big integer to modify.
 * @param[in] index The index of the bit to clear.
 * 
 * @return IOK or IERROR.
 */
int bigz_clrbit(bigz_t op, unsigned long int index);

/** 
 * @fn int bigz_tstbit(bigz_t op, unsigned long int index)
 * @brief Returns 0 if the bit at the given position is 0, 1 if it is 1.
 *
 * @param[in] op The big integer to test.
 * @param[in] index The bit to test.
 * 
 * @return 0 if the bit at the given position is 0, 1 if it is 1. If an error
 *  occurs, returns -1 and sets errno appropriately.
 */
int bigz_tstbit(bigz_t op, unsigned long int index);

/** 
 * @fn int bigz_log2(bigf_t log2n, bigz_t n, uint64_t precission)
 * @brief Sets <i>log2n</i> to the binary logarithm of <i>n</i>.
 *
 * @param[in,out] log2n Will be set to the obtained result. Must have been
 *  initialized by the caller. Note that it is a big float number.
 * @param[in] n The operand.
 * @param[in] precission The bit precission to use in the underlying floating
 *  point primitives.
 * 
 * @return IOK or IERROR.
 */
//int bigz_log2(bigf_t log2n, bigz_t n, uint64_t precission);
  
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _BIGZ_H */

/* bigz.h ends here */
