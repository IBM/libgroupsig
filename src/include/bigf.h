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

#ifndef _BIGF_H
#define _BIGF_H

#include <stdint.h>
#include "big.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * @fn bigf_t bigf_init()
 * @brief Initializes a big float number.
 *
 * Allocates memory for the mpf_t variable pointer.
 * 
 * @return An initialized big float number or NULL if error.
 */
bigf_t bigf_init();

/** 
 * @fn bigf_t bigf_init_set(bigf_t op)
 * @brief Initializes a big float number and sets it to the specified value.
 *
 * @param[in] op The big float number to use for setting the newly 
 *  initialized big float.
 * 
 * @return A pointer to the initialized and set big float number or NULL if error.
 */
bigf_t bigf_init_set(bigf_t op);
/* bigf_t bigf_init_set_ui(unsigned long int op); */

/** 
 * @fn int bigf_free(bigf_t op)
 * @brief Frees the memory allocated for the given big float number.
 *
 * @param[in,out] op The big float number to free.
 * 
 * @return IOK or IERROR.
 */
int bigf_free(bigf_t op);

/** 
 * @fn int bigf_set_prec(bigf_t rop, unsigned long int prec)
 * @brief Sets the precision of the specified big float number.
 *
 * @param[in,out] rop The big float number.
 * @param[in] prec The precision, in bits, to be used in the given big float
 *  number. 
 * 
 * @return IOK or IERROR.
 */
int bigf_set_prec(bigf_t rop, unsigned long int prec); 

/** 
 * @fn int bigf_set(bigf_t rop, bigf_t op)
 * @brief Sets the value of <i>rop</i> to <i>op</i>.
 *
 * @param[in,out] rop The big float number to set. Must have been initialized.
 * @param[in] op An initialized big float number.
 * 
 * @return IOK or IERROR.
 */
int bigf_set(bigf_t rop, bigf_t op);

/** 
 * @fn int bigf_set_z(bigf_t n, bigz_t z_n)
 * @brief Sets the value of the big float number <i>n</i> using the big integer
 *  number <i>z_n</i>.
 *
 * @param[in,out] n The big float to set. 
 * @param[in] z_n The big integer.
 * 
 * @return IOK or IERROR.
 */
int bigf_set_z(bigf_t n, bigz_t z_n);

/** 
 * @fn int bigf_set_ui(bigf_t rop, unsigned long int op)
 * @brief Sets the big float number <i>rop</i> using the value in <i>op</i>.
 *
 * @param[in,out] rop The big float number to set.
 * @param[in] op The unsigned long integer to use for setting <i>rop</i>.
 * 
 * @return IOK or IERROR.
 */
int bigf_set_ui(bigf_t rop, unsigned long int op);

/** 
 * @fn int bigf_add(bigf_t rop, bigf_t op1, bigf_t op2)
 * @brief Sets <i>rop</i> to the result of <i>op1</i>+<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the addition. Must have been
 *  initialized by the caller.
 * @param[in] op1 The first big float operand.
 * @param[in] op2 The second big float operand.
 * 
 * @return IOK or IERROR.
 */
int bigf_add(bigf_t rop, bigf_t op1, bigf_t op2);

/** 
 * @fn int bigf_add_ui(bigf_t rop, bigf_t op1, unsigned long int op2)
 * @brief Sets <i>rop</i> to the result of <i>op1</i>+<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the addition. Must have been
 *  initialized by the caller.
 * @param[in] op1 The big float operand.
 * @param[in] op2 The unsigned long int operand.
 *
 * @return IOK or IERROR.
 */
int bigf_add_ui(bigf_t rop, bigf_t op1, unsigned long int op2);

/** 
 * @fn int bigf_mul(bigf_t rop, bigf_t op1, bigf_t op2)
 * @brief Sets the value of <i>rop</i> to <i>op1</i>*<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the multiplication. Must have
 *  been initialized by the caller.
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand.
 * 
 * @return IOK or IERROR.
 */
int bigf_mul(bigf_t rop, bigf_t op1, bigf_t op2);

/** 
 * @fn int bigf_div(bigf_t rop, bigf_t op1, bigf_t op2)
 * @brief Sets <i>rop</i> to the result of <i>op1</i>/<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the division. Must have been
 *  initialized by the caller.
 * @param[in] op1 The dividend.
 * @param[in] op2 The divisor.
 * 
 * @return IOK or IERROR.
 */
int bigf_div(bigf_t rop, bigf_t op1, bigf_t op2);

/** 
 * @fn int bigf_div_ui(bigf_t rop, bigf_t op1, unsigned long int op2)
 * @brief Sets <i>rop</i> to the result of <i>op1</i>/<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the division. Must have been
 *  initialized by the caller.
 * @param[in] op1 The dividend.
 * @param[in] op2 The unsigned long int divisor.
 * 
 * @return IOK or IERROR.
 */
int bigf_div_ui(bigf_t rop, bigf_t op1, unsigned long int op2);

/** 
 * @fn int bigf_div_2exp(bigf_t rop, bigf_t op1, unsigned long int op2)
 * @brief Sets <i>rop</i> to the result of <i>op1</i>/2^<i>op2</i>.
 *
 * @param[in,out] rop Will be set to the result of the division. Must have been
 *  initialized by the caller.
 * @param[in] op1 The dividend.
 * @param[in] op2 The unsigned long int exponent of the divisor.
 * 
 * @return IOK or IERROR.
 */
int bigf_div_2exp(bigf_t rop, bigf_t op1, unsigned long int op2);

/** 
 * @fn int bigf_cmp_ui(bigf_t op1, unsigned long int op2)
 * @brief Compares <i>op1</i> and <i>op2</i>.
 *
 * @param[in] op1 The first operand.
 * @param[in] op2 The second operand.
 * 
 * @return A number less than, equal to, or greater than 0 if <i>op1</i> is less
 *  than, equal to, or greater than <i>op2</i>. On error, errno is set appropiately.
 */
int bigf_cmp_ui(bigf_t op1, unsigned long int op2);

/** 
 * @fn int bigf_floor(bigf_t rop, bigf_t n)
 * @brief Sets <i>rop</i> to floor(<i>n</i>).
 *
 * @param[in,out] rop Will be set to the result of the operation. Must have been
 *  initialized by the caller.
 * @param[in] n The operand.
 * 
 * @return IOK or IERROR.
 */
int bigf_floor(bigf_t rop, bigf_t n);

/** 
 * @fn int bigf_log2(bigf_t log2n, bigf_t n, uint64_t precission)
 * @brief Sets <i>log2n</i> to the binary logarithm of <i>n</i>, with a precission
 *  of <i>precission</i> bits.
 *
 * @param[in,out] log2n Will be set to the result of the operation. Must have been 
 *  initialized by the caller. 
 * @param[in] n The operand.
 * @param[in] precission The number of bits of precission.
 * 
 * @return IOK or IERROR.
 */
int bigf_log2(bigf_t log2n, bigf_t n, uint64_t precission);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _BIGF_H */

/* bigf.h ends here */
