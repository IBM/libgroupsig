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

#ifndef _GS_SPK_H
#define _GS_SPK_H

#include "types.h"
#include "sysenv.h"
#include "bigz.h"
#include "shim/pbc_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct spk_dlog_t
 * @brief Data structure for convenional discrete log proofs.
 */
typedef struct _spk_dlog_t {
  pbcext_element_Fr_t *c; /**< c component of conventional dlog proofs. */
  pbcext_element_Fr_t *s; /**< s component of conventional dlog proofs. */
} spk_dlog_t;

/**
 * @struct spk_rep_t
 * @brief Data structure for general representation proofs.
 */
typedef struct _spk_rep_t {
  pbcext_element_Fr_t *c; /**< c component of representation proofs. */
  pbcext_element_Fr_t **s; /**< Array of pointers to s components representation 
			      proofs. */
  uint16_t ns; /**< Size of the s array */
} spk_rep_t;

typedef struct _spk_pairing_homomorphism_G2_t {
  pbcext_element_Fr_t *c;
  pbcext_element_G2_t *s;
} spk_pairing_homomorphism_G2_t;

/**
 * @fn spk_dlog_t* spk_dlog_init(void)
 * Allocates memory for a spk_dlog_t structure.
 * 
 * @return A pointer to the allocated structure or NULL if error.
 */
spk_dlog_t* spk_dlog_init(void);

/**
 * @fn int spk_dlog_free(spk_dlog_t *spk)
 * Frees the memory allocated for a spk_dlog_t structure.
 * 
 * @param[in,out] spk The spk_dlog_t* structure to free.
 *
 * @return IOK or IERROR.
 */
int spk_dlog_free(spk_dlog_t *spk);

/**
 * @fn int spk_dlog_copy(spk_dlog_t *dst, spk_dlog_t *src)
 * Copies the source spk dlog into dst.
 * 
 * @param[in,out] dst The destination spk_dlog_t* structure.
 *  Must have been initialized by the caller.
 * @param[in,out] src The source spk_dlog_t* structure.
 *
 * @return IOK or IERROR.
 */
  
int spk_dlog_copy(spk_dlog_t *dst, spk_dlog_t *src);

/**
 * @fn int spk_dlog_G1_sign(spk_dlog_t_t *pi, 
 *                          pbcext_element_G1_t *G, 
 *                          pbcext_element_G1_t *g,
 *                          pbcext_element_Fr_t *x, 
 *                          byte_t *msg, 
 *                          uint32_t size)
 * Computes a conventional discrete log signature proof of knowledge for:
 *   SPK[x: g^x mod p = G](msg).
 * Where g and G are elements of G1 in a bilinear pairing.
 *
 * @param[in,out] pi An initialized spk_dlog_t structure.
 * @param[in] G The result of g^x mod p.
 * @param[in] g The modular exponentiation base.
 * @param[in] x The (secret) exponent.
 * @param[in] msg The message to sign.
 * @param[in] size The size, in bytes, of the message. 
 *
 * @return IOR or IERROR.
 */
int spk_dlog_G1_sign(spk_dlog_t *pi,
		     pbcext_element_G1_t *G,
		     pbcext_element_G1_t *g,
		     pbcext_element_Fr_t *x,
		     byte_t *msg,
		     uint32_t size);

/**
 * @fn int spk_dlog_G1_verify(uint8_t *ok,
 *                            pbcext_element_G1_t *G, 
 *                            pbcext_element_G1_t *g,
 *                            byte_t *msg, 
 *                            uint32_t size)
 * Verifies a conventional discrete log signature proof of knowledge for:
 *   SPK[x: g^x mod p = G](msg).
 * Where g and G are elements of G1 in a bilinear pairing.
 *
 * @param[in,out] ok 1 if the proof verifies, 0 if not.
 * @param[in] G The result of g^x mod p.
 * @param[in] g The modular exponentiation base.
 * @param[in] q The working modulo.
 * @param[in] pi The proof.
 * @param[in] msg The signed message.
 * @param[in] size The size, in bytes, of the message.
 *
 * @return IOR or IERROR.
 */
int spk_dlog_G1_verify(uint8_t *ok,
		       pbcext_element_G1_t *G,
		       pbcext_element_G1_t *g,
		       spk_dlog_t *pi,
		       byte_t *msg, uint32_t size);

/**
 * @fn int spk_dlog_GT_sign(spk_dlog_t_t *pi, 
 *                          pbcext_element_GT_t *G, 
 *                          pbcext_element_GT_t *g,
 *                          pbcext_element_Fr_t *x, 
 *                          byte_t *msg, 
 *                          uint32_t size)
 * Computes a conventional discrete log signature proof of knowledge for:
 *   SPK[x: g^x mod p = G](msg).
 * Where g and G are elements of GT in a bilinear pairing.
 *
 * @param[in,out] pi An initialized spk_dlog_t structure.
 * @param[in] G The result of g^x mod p.
 * @param[in] g The modular exponentiation base.
 * @param[in] x The (secret) exponent.
 * @param[in] msg The message to sign.
 * @param[in] size The size, in bytes, of the message. 
 *
 * @return IOR or IERROR.
 */
int spk_dlog_GT_sign(spk_dlog_t *pi,
		     pbcext_element_GT_t *G,
		     pbcext_element_GT_t *g,
		     pbcext_element_Fr_t *x,
		     byte_t *msg,
		     uint32_t size);

/**
 * @fn int spk_dlog_GT_verify(uint8_t *ok,
 *                            pbcext_element_GT_t *G, 
 *                            pbcext_element_GT_t *g,
 *                            byte_t *msg, 
 *                            uint32_t size)
 * Verifies a conventional discrete log signature proof of knowledge for:
 *   SPK[x: g^x mod p = G](msg).
 * Where g and G are elements of GT in a bilinear pairing.
 *
 * @param[in,out] ok 1 if the proof verifies, 0 if not.
 * @param[in] G The result of g^x mod p.
 * @param[in] g The modular exponentiation base.
 * @param[in] q The working modulo.
 * @param[in] pi The proof.
 * @param[in] msg The signed message.
 * @param[in] size The size, in bytes, of the message.
 *
 * @return IOR or IERROR.
 */
int spk_dlog_GT_verify(uint8_t *ok,
		       pbcext_element_GT_t *G,
		       pbcext_element_GT_t *g,
		       spk_dlog_t *pi,
		       byte_t *msg, uint32_t size);  

/**
 * @fn int spk_dlog_get_size(spk_dlog_t *proof)
 * Returns the number of bytes needed to represent the proof (in raw format.)
 *
 * @param[in] proof The proof.
 * 
 * @return The size in bytes required to represent the proof. -1 if error.
 */
int spk_dlog_get_size(spk_dlog_t *proof);

/**
 * @fn int spk_dlog_export_fd(spk_dlog_t *proof, FILE *fd)
 * @brief Exports a dlog proof as a byte array into the given file,
 *
 * The format of the produced bytearray will be will be:
 *
 *    | sizeof(c) | c | sizeof(s) | s
 *
 * Where the sizeof fields are ints indicating the number of bytes of 
 * the following field.
 *
 * @param[in] proof The proof to export.
 * @param[in] fd The destination file descriptor. Must be big enough to store 
 *  the result.
 *
 * @return IOK or IERROR.
 */
int spk_dlog_export_fd(spk_dlog_t *proof, FILE *fd);

/**
 * @fn int spk_dlog_export(byte_t **bytes, uint64_t *len, spk_dlog_t *proof)
 * @brief Exports a dlog proof to a bytearray,
 *
 * The format of the produced bytearray will be:
 *
 *    | sizeof(c) | c | sizeof(s) | s
 *
 * Where the sizeof fields are ints indicating the number of bytes of 
 * the following field.
 *
 * @param[in,out] bytes The byte array to write the spk into. If *bytes is NULL,
 *  memory will be internally allocated.
 * @param[in,out] len Will be set to the number of bytes written into bytes.
 * @param[in] proof The spk to export.
 *
 * @return IOK or IERROR.
 */
int spk_dlog_export(byte_t **bytes,
		    uint64_t *len,
		    spk_dlog_t *proof);

/**
 * @fn spk_dlog_t* spk_dlog_import_fd(FILE *fd)
 * @brief Import a representation of the given key from a file descriptor.
 * Expects the same format as the output from _export_fd().
 *
 * @param[in] The file descriptor to read from.
 *
 * @return The imported proof, or NULL if error.
 */
spk_dlog_t* spk_dlog_import_fd(FILE *fd);

/**
 * @fn spk_dlog_t* spk_dlog_import(byte_t *bytes, uint64_t *len)
 * @brief Exports a dlog proof to a bytearray,
 *
 * The format of the received bytearray must be:
 *
 *    | sizeof(c) | c | sizeof(s) | s
 *
 * Where the sizeof fields are ints indicating the number of bytes of 
 * the following field.
 *
 * @param[in] bytes The byte array containing the exported byte array).
 * @param[in] len The length of the byte array.
 *
 * @return A pointer to the allocated structure or NULL if error.
 */
spk_dlog_t* spk_dlog_import(byte_t *bytes, uint64_t *len);
  
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


  
/**
 * @fn spk_pairing_homomorphism_G2_t* spk_pairing_homomorphism_G2_init(void)
 * Allocates memory for a spk_pairing_homomorphism_G2_t structure.
 * 
 * @return A pointer to the allocated structure or NULL if error.
 */  
spk_pairing_homomorphism_G2_t* spk_pairing_homomorphism_G2_init();

/**
 * @fn int spk_pairing_homomorphism_G2_free(spk_pairing_homomorphism_G2_t *spk)
 * Frees the memory allocated for a spk_pairing_homomorphism_G2_t structure.
 * 
 * @param[in,out] spk The spk_pairing_homomorphism_G2_t* structure to free.
 *
 * @return IOK or IERROR.
 */  
int spk_pairing_homomorphism_G2_free(spk_pairing_homomorphism_G2_t *spk);
  
/**
 * @fn int spk_pairing_homomorphism_G2_sign(spk_pairing_homomorphism_G2_t *pi,
 *				            pbcext_element_G1_t *g,
 *				            pbcext_element_GT_t *G,
 *				            pbcext_element_G2_t *xx,
 *				            byte_t *msg,
 *				            uint32_t size)
 * Given a pairing operation e from G1 x G2 -> GT, computes an SPK
 * of a preimage of G given the group homomorphism from G2 to GT defined
 * by e(g,\cdot). 
 *
 * Check https://www.crypto.ethz.ch/publications/files/Maurer15.ps 
 * for details.
 *
 * @param[in,out] pi An initialized spk_pairing_homomorphism_G2_t structure.
 * @param[in] g The G1 value defining the homomorphism.
 * @param[in] G The publicly known result of e(g, xx)
 * @param[in] xx The (secret) preimage.
 * @param[in] msg The message to sign.
 * @param[in] size The size, in bytes, of the message. 
 *
 * @return IOR or IERROR.
 */
int spk_pairing_homomorphism_G2_sign(spk_pairing_homomorphism_G2_t *pi,
				     pbcext_element_G1_t *g,
				     pbcext_element_GT_t *G,
				     pbcext_element_G2_t *xx,
				     byte_t *msg,
				     uint32_t size);

/**
 * @fn int spk_pairing_homomorphism_G2_verify(uint8_t *ok,
 *				       pbcext_element_G1_t *g,
 *				       pbcext_element_GT_t *G,
 *				       spk_pairing_homomorphism_G2_t *pi,
 *				       byte_t *msg,
 *				       uint32_t size)
 * Verifies an SPK of a preimage of G given the group homomorphism from G2 to GT
 * defined by e(g, \cdot). 
 * 
 * Check https://www.crypto.ethz.ch/publications/files/Maurer15.ps 
 * for details.
 *
 * @param[in,out] ok Will be set to 1 if the proof verifies, 0 if not.
 * @param[in] g The G1 value defining the homomorphism.
 * @param[in] G The publicly known result of e(g, xx)
 * @param[in] pi The proof.
 * @param[in] msg The signed message.
 * @param[in] size The size, in bytes, of the message.
 *
 * @return IOR or IERROR.
 */  
int spk_pairing_homomorphism_G2_verify(uint8_t *ok,
				       pbcext_element_G1_t *g,
				       pbcext_element_GT_t *G,
				       spk_pairing_homomorphism_G2_t *pi,
				       byte_t *msg,
				       uint32_t size);

/**
 * @fn spk_pairing_homomorphism_G2_get_size(spk_pairing_homomorphism_G2_t *proof);
 * Returns the number of bytes needed to represent the proof (in raw format.)
 *
 * @param[in] proof The proof.
 * 
 * @return The size in bytes required to represent the proof. -1 if error.
 */  
int spk_pairing_homomorphism_G2_get_size(spk_pairing_homomorphism_G2_t *proof);

/**
 * @fn int spk_pairing_homomorphism_G2_export(byte_t **bytes, 
 *                                            uint64_t *len, 
 *                                            spk_dlog_t *proof)
 * @brief Exports a group homomorphism preimage spk to a bytearray,
 *
 * The format of the produced bytearray will be:
 *
 *    | sizeof(c) | c | sizeof(s) | s
 *
 * Where the sizeof fields are ints indicating the number of bytes of 
 * the following field.
 *
 * @param[in,out] bytes The byte array to write the spk into. If *bytes is NULL,
 *  memory will be internally allocated.
 * @param[in,out] len Will be set to the number of bytes written into bytes.
 * @param[in] proof The spk to export.
 *
 * @return IOK or IERROR.
 */  
int
spk_pairing_homomorphism_G2_export(byte_t **bytes,
				   uint64_t *len,
				   spk_pairing_homomorphism_G2_t *proof);

/**
 * @fn spk_pairing_homomorphism_G2_t* spk_dlog_import(byte_t *bytes, 
 *                                                    uint64_t *len)
 * @brief Exports a group homomorphism preimage spk to a bytearray,
 *
 * The format of the received bytearray must be:
 *
 *    | sizeof(c) | c | sizeof(s) | s
 *
 * Where the sizeof fields are ints indicating the number of bytes of 
 * the following field.
 *
 * @param[in] bytes The byte array containing the exported byte array).
 * @param[in] len The length of the byte array.
 *
 * @return A pointer to the allocated structure or NULL if error.
 */  
spk_pairing_homomorphism_G2_t*
spk_pairing_homomorphism_G2_import(byte_t *bytes, uint64_t *len);  

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GS_SPK_H */
