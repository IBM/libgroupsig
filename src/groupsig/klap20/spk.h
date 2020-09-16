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

/**
 * DISCLAIMER: This file (and its source companion) will disappear once
 * issue23 is solved.
 */

#ifndef _KLAP20_SPK_H
#define _KLAP20_SPK_H

#include "types.h"
#include "sysenv.h"
#include "shim/pbc_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

  typedef struct _klap20_spk0_t {
    pbcext_element_Fr_t *c; /**< c component of representation proofs. */
    pbcext_element_Fr_t **s; /**< Array of pointers to s components representation 
				proofs. */  
    uint16_t ns; /**< Size of the s array */
  };

/**
 * @fn spk_rep_t* spk_rep_init(uint16_t ns)
 * Allocates memory for a spk_rep_t structure.
 *
 * @param[in] ns The number of private values in the proof.
 * 
 * @return A pointer to the allocated structure or NULL if error.
 */
spk_rep_t* spk_rep_init(uint16_t ns);

/**
 * @fn int spk_rep_init(spk_rep_t *spk)
 * Frees the memory allocated for a spk_rep_t structure.
 * 
 * @param[in,out] spk The spk_rep_t* structure to free.
 *
 * @return IOK or IERROR.
 */
int spk_rep_free(spk_rep_t *spk);

/**
 * @fn int spk_rep_copy(spk_rep_t *dst, spk_rep_t *src)
 * Copies the src spk rep into dst.
 * 
 * @param[in,out] dst The destination spk_rep_t* structure.
 *  Must have been initialized by the caller.
 * @param[in,out] src The source spk_rep_t* structure.
 *
 * @return IOK or IERROR.
 */
  
int spk_rep_copy(spk_rep_t *dst, spk_rep_t *src);  

/**
 * @fn int spk_rep_sign(spk_rep_t *pi,
 *                      element_t *y[], uint16_t ny,
 *	                element_t *g[], uint16_t ng,
 *		        element_t *x[], uint16_t nx,
 *		        uint16_t **i, uint16_t ni,
 *		        uint16_t *prods,
 *		        byte_t *msg, uint32_t size)
 * Computes a general representation signature proof of knowledge (see 
 * the cs97 paper for details) over the message msg.
 *
 * @param[in,out] pi An initilized spk_rep_t structure.
 * @param[in] y An array with the y group elements s.t. y[i] = prod_i g[j_i]^x[k_i] for some i, j, k.
 * @param[in] ny The size of the array y.
 * @param[in] g An array with the g group elements s.t. y[i] = prod_i g[j_i]^x[k_i] for some i, j, k.
 * @param[in] ng The size of the array g.
 * @param[in] x An array with the (secret) exponents s.t. y[i] = prod_l g[j_i]^x[k_i] for some i, j, k.
 * @param[in] nx The size of the array x.
 * @param[in] i An array of pairs of indexes, indicating how the j's and k's relate to each 
 *  other in the previous arrays.
 * @param[in] ni The size of the array i.
 * @param[in] prods An array indicating the length of the products in the 
 * previous formulae, in number of multiplicands (can be 1.) Has size ny.
 * @param[in] msg The message to sign.
 * @param[in] size The size, in bytes, of the message. 
 *
 * @return IOR or IERROR.
 */
int spk_rep_sign(spk_rep_t *pi,
		 pbcext_element_G1_t *y[], uint16_t ny,
		 pbcext_element_G1_t *g[], uint16_t ng,
		 pbcext_element_Fr_t *x[], uint16_t nx,
		 uint16_t i[][2], uint16_t ni,
		 uint16_t *prods,
		 byte_t *msg, uint32_t size);

/**
 * @fn int spk_rep_verify(uint8_t *ok,
 *		          element_t *y[], uint16_t ny,
 *		          element_t *g[], uint16_t ng,
 *		          uint16_t **i, uint16_t ni,
 *		          uint16_t *prods,
 *		          spk_rep_t *pi,
 *		          byte_t *msg, uint32_t size)
 *
 * Verifies a general representaiton signature proof of knowledge (see
 * the cs97 paper for details) over the message msg.
 *
 * @param[in,out] ok 1 if the proof verifies, 0 if not.
 * @param[in] y An array with the y group elements s.t. y[i] = prod_i g[j_i]^x[k_i] for some i, j, k.
 * @param[in] ny The size of the array y.
 * @param[in] g An array with the g group elements s.t. y[i] = prod_i g[j_i]^x[k_i] for some i, j, k.
 * @param[in] ng The size of the array g.
 * @param[in] i An array of pairs of indexes, indicating how the j's and k's relate to each 
 *  other in the previous arrays.
 * @param[in] ni The size of the array i.
 * @param[in] prods An array indicating the length of the products in the previous formulae. 
 *  Has size ny.
 * @param[in] pi The proof.
 * @param[in] msg The signed message.
 * @param[in] size The size, in bytes, of the message.
 *
 * @return IOR or IERROR.
 */
int spk_rep_verify(uint8_t *ok,
		   pbcext_element_G1_t *y[], uint16_t ny,
		   pbcext_element_G1_t *g[], uint16_t ng,
		   uint16_t i[][2], uint16_t ni,
		   uint16_t *prods,
		   spk_rep_t *pi,
		   byte_t *msg, uint32_t size);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _KLAP20_SPK_H */
