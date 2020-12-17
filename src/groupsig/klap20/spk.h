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
#include "crypto/spk.h"

#ifdef __cplusplus
extern "C" {
#endif
  
  typedef struct _klap20_spk0_t {
    pbcext_element_Fr_t *c; /**< c component of representation proofs. */
    pbcext_element_Fr_t **s; /**< Array of pointers to s components representation 
				proofs. */  
    uint16_t ns; /**< Size of the s array */
  } klap20_spk0_t;

  typedef struct _klap20_spk1_t {
    pbcext_element_Fr_t *c;
    pbcext_element_G2_t *s;
    pbcext_element_GT_t *tau;
  } klap20_spk1_t;

  /**
   * @fn int klap20_spk0_sign(spk_rep_t *pi,
   *                          void *y[], uint16_t ny,
   *	                      void *g[], uint16_t ng,
   *		              void *x[], uint16_t nx,
   *		              uint16_t **i, uint16_t ni,
   *		              uint16_t *prods,
   *		              byte_t *msg, uint32_t size)
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
  int klap20_spk0_sign(spk_rep_t *pi,
		       void *y[], uint16_t ny,
		       void *g[], uint16_t ng,
		       pbcext_element_Fr_t *x[], uint16_t nx,
		       uint16_t i[][2], uint16_t ni,
		       uint16_t *prods,
		       byte_t *msg, uint32_t size);

  /**
   * @fn int spk_rep_verify(uint8_t *ok,
   *		          void *y[], uint16_t ny,
   *		          void *g[], uint16_t ng,
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
  int klap20_spk0_verify(uint8_t *ok,
			 void *y[], uint16_t ny,
			 void *g[], uint16_t ng,
			 uint16_t i[][2], uint16_t ni,
			 uint16_t *prods,
			 spk_rep_t *pi,
			 byte_t *msg, uint32_t size);

  /**
   * @fn klap20_spk1_t* klap20_spk1_init();
   * Initializes a data structures for SPKs used in open proofs in KLAP20.
   *
   * NOTE: This function will be removed with issue23.
   *
   * @return A pointer to the allocated structure.
   */  
  klap20_spk1_t* klap20_spk1_init();

  /**
   * @fn int klap20_spk1_free(klap20_spk1_t *pi);
   * Frees the memory allocated for a data structures for SPKs used in open 
   * proofs in KLAP20.
   *
   * NOTE: This function will be removed with issue23.
   *
   * @param[in,out] pi The structure to free.
   * 
   * @return IOK or IERROR.
   */  
  int klap20_spk1_free(klap20_spk1_t *pi);

  /**
   * @fn int klap20_spk1_get_size(klap20_spk1_t *pi);
   * Returns the memory needed to store, in an array of bytes, a data structures
   * for SPKs used in open proofs in KLAP20.
   *
   * NOTE: This function will be removed with issue23.
   *
   * @param[in,out] pi The structure.
   * 
   * @return The number of bytes, or -1 if error.
   */
  int klap20_spk1_get_size(klap20_spk1_t *pi);

  /**
   * @fn int klap20_spk1_export(byte_t **bytes, uint64_t *len, klap20_spk1_t *pi);
   * Exports the given proof into an array of bytes.
   *
   * The produced format is as follows:
   * 
   * | size_c | c | size_s | s | size_tau | tau |
   *
   * NOTE: This function will be removed with issue23.
   *
   * @param[in,out] bytes A pointer to an array of bytes. If *bytes is NULL,
   *  memory will be internally allocated. Otherwise, the given array must be
   *  big enough to store the result.
   * @param[in,out] len Will be set to the number of bytes in the exported array.
   * @param[in] pi The SPK to export.
   * 
   * @return The number of bytes, or -1 if error.
   */  
  int klap20_spk1_export(byte_t **bytes, uint64_t *len, klap20_spk1_t *pi);
  
  /**
   * @fn klap20_spk1_t* klap20_spk1_import(byte_t *bytes, uint64_t *len);
   * Imports a KLAP20 SPK of opening from the given array of bytes.
   *
   * NOTE: This function will be removed with issue23.
   *
   * @param[in] bytes A pointer to the array of bytes containing the exported 
   *  SPK.
   * @param[in] len The number of bytes in the given array of bytes.
   * 
   * @return A pointer to the imported SPK, or NULL if error.
   */  
  klap20_spk1_t* klap20_spk1_import(byte_t *bytes, uint64_t *len);

  /**
   * @fn int klap20_spk1_sign(klap20_spk1_t *pi,
   *                          pbcext_element_G2_t *xx,
   *    	  	      pbcext_element_G1_t *g1,
   *		              pbcext_element_G1_t *g2,
   *		              pbcext_element_GT_t *e1,
   *		              pbcext_element_GT_t *e2,
   *		              byte_t *msg,
   *		              uint32_t size);
   * Computes an SPK proving opening correctness in KLAP20.
   *
   * NOTE: This function will be removed with issue23.
   *
   * @param[in,out] pi An initialized SPK structure for KLAP20 openings. 
   * @param[in] xx The secret.
   * @param[in] g1 G1 element defining the first homomorphism.
   * @param[in] g2 G1 element defining the second homomorphism.
   * @param[in] e1 GT element value of the first homomorphism: e1 = e(g1, xx).
   * @param[in] e2 GT element value of the second homomorphism: e2 = e(g2, xx).
   * @param[in] msg The message to include in the SPK.
   * @param[in] size The number of bytes in the message.
   * 
   * @return IOK or IERROR.
   */  
  int klap20_spk1_sign(klap20_spk1_t *pi,
		       pbcext_element_G2_t *xx,
		       pbcext_element_G1_t *g1,
		       pbcext_element_G1_t *g2,
		       pbcext_element_GT_t *e1,
		       pbcext_element_GT_t *e2,
		       byte_t *msg,
		       uint32_t size);

  /**
   * @fn int klap20_spk1_verify(uint8_t *ok,
   *                            klap20_spk1_t *pi,
   *                            pbcext_element_G1_t *g1,
   *                            pbcext_element_G1_t *g2,
   *			        pbcext_element_GT_t *e1,
   *			        pbcext_element_GT_t *e2,
   *			        byte_t *msg,
   *			        uint32_t size);
   * Verifies an SPK proving opening correctness in KLAP20.
   *
   * NOTE: This function will be removed with issue23.
   *
   * @param[in,out] ok A pointer to a uint8_t. The pointed uint will be set to
   *  1 if the SPK is correct, to 0 otherwise.
   * @param[in] pi The proof to verify.
   * @param[in] g1 G1 element defining the first homomorphism.
   * @param[in] g2 G1 element defining the second homomorphism.
   * @param[in] e1 GT element value of the first homomorphism: e1 = e(g1, xx).
   * @param[in] e2 GT element value of the second homomorphism: e2 = e(g2, xx).
   * @param[in] msg The message included in the SPK.
   * @param[in] size The number of bytes in the message.
   * 
   * @return IOK or IERROR.
   */    
  int klap20_spk1_verify(uint8_t *ok,
			 klap20_spk1_t *pi,
			 pbcext_element_G1_t *g1,
			 pbcext_element_G1_t *g2,
			 pbcext_element_GT_t *e1,
			 pbcext_element_GT_t *e2,
			 byte_t *msg,
			 uint32_t size);  
  
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _KLAP20_SPK_H */
