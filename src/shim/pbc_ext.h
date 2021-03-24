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

#ifndef _PBC_EXT_H
#define _PBC_EXT_H

#include "types.h"
#include "big.h"

/* Right now, the module is based on the MCL library, but this might change in
   the future. Check https://github.com/herumi/mcl/blob/master/api.md for 
   details on MCL. */
/* Previously, we used PBC, which has become quite outdated since the creation 
   of libgroupsig. However, you might see some similarities in the API we 
   offer. */
#include "mcl/bn_c384_256.h"
#include "mcl/bn.h"

#ifdef __cplusplus
extern "C" {
#endif

  /** Data structures, typedefs and constants **/
  typedef mclBnFp pbcext_element_Fp_t;
  typedef mclBnFr pbcext_element_Fr_t;
  typedef mclBnG1 pbcext_element_G1_t;
  typedef mclBnG2 pbcext_element_G2_t;
  typedef mclBnGT pbcext_element_GT_t;

#define BLS12_381 MCL_BLS12_381
#define BLS12_381_P "1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569"

#define BLS12_381_Q "1 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"  

  //typedef int pbcext_curve_t;

  /* #define MAX_Fr_SIZE_STR 48 */
  /* #define MAX_Fp_SIZE_STR 48 */
  /* #define MAX_G1_SIZE_STR 144 */
  /* #define MAX_G2_SIZE_STR 144 */
  /* #define MAX_GT_SIZE_STR 144 */

  /** Initialization and deinitialization **/

  int pbcext_init(int curve);

  /** 
   * @fn pbcext_element_Fp_t* pbcext_element_init_Fp()
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fp field associated to curve c.
   *
   * 
   * @return A pointer to the allocated element, or NULL if error.
   */
  pbcext_element_Fp_t* pbcext_element_Fp_init(void);

  /** 
   * @fn int pbcext_element_Fp_free(pbcext_element_Fp_t *e)
   * @brief Frees an allocated Fp element.
   *
   * @param[in,out] e The element to free.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_free(pbcext_element_Fp_t *e);

  /** 
   * @fn pbcext_element_Fr_t* pbcext_element_init_Fr()
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fr field.
   * 
   * @return A pointer to the allocated element, or NULL if error.
   */
  pbcext_element_Fr_t* pbcext_element_Fr_init(void);

  /** 
   * @fn int pbcext_element_Fr_free(pbcext_element_Fr_t *e)
   * @brief Frees an allocated Fr element.
   *
   * @param[in,out] e The element to free.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_free(pbcext_element_Fr_t *e);

  /** 
   * @fn pbcext_element_G1_t* pbcext_element_G1_init(void)
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fp field.
   * 
   * @return A pointer to the allocated element, or NULL if error.
   */
  pbcext_element_G1_t* pbcext_element_G1_init(void);

  /** 
   * @fn int pbcext_element_G1_free(pbcext_element_G1_t *e)
   * @brief Frees an allocated G1 element.
   *
   * @param[in,out] e The element to free.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_free(pbcext_element_G1_t *e);

  /** 
   * @fn pbcext_element_G2_t* pbcext_element_G2_init(void)
   * @brief Allocates (and initializes, when possible) a new element in the
   * G2 field.
   *
   * @return A pointer to the allocated element, or NULL if error.
   */
  pbcext_element_G2_t* pbcext_element_G2_init(void);

  /** 
   * @fn int pbcext_element_G2_free(pbcext_element_G2_t *e)
   * @brief Frees an allocated G2 element.
   *
   * @param[in,out] e The element to free.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_free(pbcext_element_G2_t *e);

  /** 
   * @fn pbcext_element_GT_t* pbcext_element_GT_init(void)
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fr field.
   *
   * @return A pointer to the allocated element, or NULL if error.
   */
  pbcext_element_GT_t* pbcext_element_GT_init(void);

  /** 
   * @fn int pbcext_element_GT_free(pbcext_element_GT_t *e)
   * @brief Frees an allocated GT element.
   *
   * @param[in,out] e The element to free.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_free(pbcext_element_GT_t *e);

  /** 
   * @fn int pbcext_element_Fp_free(pbcext_element_Fp_t *e)
   * @brief Sets e to 0.
   *
   * @param[in,out] e The element to set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_clear(pbcext_element_Fp_t *e);

  /** 
   * @fn int pbcext_element_Fr_free(pbcext_element_Fr_t *e)
   * @brief Sets e to 0.
   *
   * @param[in,out] e The element to set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_clear(pbcext_element_Fr_t *e); 

  /** 
   * @fn int pbcext_element_G1_free(pbcext_element_G1_t *e)
   * @brief Sets e to 0.
   *
   * @param[in,out] e The element to set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_clear(pbcext_element_G1_t *e);

  /** 
   * @fn int pbcext_element_G2_free(pbcext_element_G2_t *e)
   * @brief Sets e to 0.
   *
   * @param[in,out] e The element to set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_clear(pbcext_element_G2_t *e);

  /** 
   * @fn int pbcext_element_GT_free(pbcext_element_GT_t *e)
   * @brief Sets e to 0.
   *
   * @param[in,out] e The element to set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_clear(pbcext_element_GT_t *e); 
  
  /** 
   * @fn int pbcext_element_Fp_init(pbcext_element_GT_t **e, pbcext_curve_t *c)
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fr field associated to curve c.
   *
   * @param[in,out] e Will be set to the newly allocated element.
   * @param[in] c The curve defining the field for e.
   * 
   * @return IOK or IERROR.
   */
  //int pbcext_element_init_same_as(pbcext_element_t **dst, pbcext_element_t *src);

  /** 
   * @fn int pbcext_element_Fp_set(pbcext_element_Fp_t *dst, pbcext_element_Fp_t *src)
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fr field associated to curve c.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] src The element to assign from.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_set(pbcext_element_Fp_t *dst, pbcext_element_Fp_t *src);

  /** 
   * @fn int pbcext_element_Fr_set(pbcext_element_Fr_t *dst, pbcext_element_Fr_t *src)
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fr field associated to curve c.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] src The element to assign from.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_set(pbcext_element_Fr_t *dst, pbcext_element_Fr_t *src);

  /** 
   * @fn int pbcext_element_G1_set(pbcext_element_G1_t *dst, pbcext_element_G1_t *src)
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fr field associated to curve c.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] src The element to assign from.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_set(pbcext_element_G1_t *dst, pbcext_element_G1_t *src);

  /** 
   * @fn int pbcext_element_G2_set(pbcext_element_G2_t *dst, pbcext_element_G2_t *src)
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fr field associated to curve c.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] src The element to assign from.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_set(pbcext_element_G2_t *dst, pbcext_element_G2_t *src);

  /** 
   * @fn int pbcext_element_GT_set(pbcext_element_GT_t *dst, pbcext_element_GT_t *src)
   * @brief Allocates (and initializes, when possible) a new element in the
   * Fr field associated to curve c.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] src The element to assign from.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_set(pbcext_element_GT_t *dst, pbcext_element_GT_t *src);

  /** 
   * @fn int pbcext_element_Fp_random(pbcext_element_Fp_t *e)
   * @brief Sets e randomly from the set of possible points.
   *
   * @param[in,out] e The element to be set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_random(pbcext_element_Fp_t *e);

  /** 
   * @fn int pbcext_element_random_Fr(pbcext_element_Fr_t *e)
   * @brief Sets e randomly from the set of possible points.
   *
   * @param[in,out] e The element to be set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_random(pbcext_element_Fr_t *e);

  /** 
   * @fn int pbcext_element_random_G1(pbcext_element_G1_t *e)
   * @brief Sets e randomly from the set of possible points.
   *
   * @param[in,out] e The element to be set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_random(pbcext_element_G1_t *e);

  /** 
   * @fn int pbcext_element_random_G2(pbcext_element_G2_t *e)
   * @brief Sets e randomly from the set of possible points.
   *
   * @param[in,out] e The element to be set.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_random(pbcext_element_G2_t *e);

  /** 
   * @fn int pbcext_element_Fr_add(pbcext_element_Fr_t *dst,
   *                               pbcext_element_Fr_t *e1,
   *                               pbcext_element_Fr_t *e2)
   * @brief Sets dst to e1+e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_add(pbcext_element_Fr_t *dst,
			    pbcext_element_Fr_t *e1,
			    pbcext_element_Fr_t *e2);

  /** 
   * @fn int pbcext_element_Fp_add(pbcext_element_Fp_t *dst,
   *                               pbcext_element_Fp_t *e1,
   *                               pbcext_element_Fp_t *e2)
   * @brief Sets dst to e1+e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_add(pbcext_element_Fp_t *dst,
			    pbcext_element_Fp_t *e1,
			    pbcext_element_Fp_t *e2);

  /** 
   * @fn int pbcext_element_G1_add(pbcext_element_G1_t *dst,
   *                               pbcext_element_G1_t *e1,
   *                               pbcext_element_G1_t *e2)
   * @brief Sets dst to e1+e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_add(pbcext_element_G1_t *dst,
			    pbcext_element_G1_t *e1,
			    pbcext_element_G1_t *e2);

  /** 
   * @fn int pbcext_element_G2_add(pbcext_element_G2_t *dst,
   *                               pbcext_element_G2_t *e1,
   *                               pbcext_element_G2_t *e2)
   * @brief Sets dst to e1+e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_add(pbcext_element_G2_t *dst,
			    pbcext_element_G2_t *e1,
			    pbcext_element_G2_t *e2);

  /** 
   * @fn int pbcext_element_Fr_sub(pbcext_element_Fr_t *dst,
   *                               pbcext_element_Fr_t *e1,
   *                               pbcext_element_Fr_t *e2)
   * @brief Sets dst to e1-e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_sub(pbcext_element_Fr_t *dst,
			    pbcext_element_Fr_t *e1,
			    pbcext_element_Fr_t *e2);

  /** 
   * @fn int pbcext_element_Fr_sub(pbcext_element_Fr_t *dst,
   *                               pbcext_element_Fr_t *e1,
   *                               pbcext_element_Fr_t *e2)
   * @brief Sets dst to e1-e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_sub(pbcext_element_Fp_t *dst,
			    pbcext_element_Fp_t *e1,
			    pbcext_element_Fp_t *e2);

  /** 
   * @fn int pbcext_element_G1_sub(pbcext_element_G1_t *dst,
   *                               pbcext_element_G1_t *e1,
   *                               pbcext_element_G1_t *e2)
   * @brief Sets dst to e1-e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_sub(pbcext_element_G1_t *dst,
			    pbcext_element_G1_t *e1,
			    pbcext_element_G1_t *e2);

  /** 
   * @fn int pbcext_element_G2_sub(pbcext_element_G2_t *dst,
   *                               pbcext_element_G2_t *e1,
   *                               pbcext_element_G2_t *e2)
   * @brief Sets dst to e1-e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_sub(pbcext_element_G2_t *dst,
			    pbcext_element_G2_t *e1,
			    pbcext_element_G2_t *e2);

  /** 
   * @fn int pbcext_element_Fr_neg(pbcext_element_Fr_t *dst,
   *                               pbcext_element_Fr_t *e)
   * @brief Sets dst to -e
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The element to negate.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_neg(pbcext_element_Fr_t *dst, pbcext_element_Fr_t *e);

  /** 
   * @fn int pbcext_element_Fp_neg(pbcext_element_Fp_t *dst,
   *                               pbcext_element_Fp_t *e)
   * @brief Sets dst to -e
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The element to negate.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_neg(pbcext_element_Fp_t *dst, pbcext_element_Fp_t *e);

  /** 
   * @fn int pbcext_element_G1_neg(pbcext_element_G1_t *dst,
   *                               pbcext_element_G1_t *e)
   * @brief Sets dst to -e
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The element to negate.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_neg(pbcext_element_G1_t *dst, pbcext_element_G1_t *e);

  /** 
   * @fn int pbcext_element_G2_neg(pbcext_element_G2_t *dst,
   *                               pbcext_element_G2_t *e)
   * @brief Sets dst to -e
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The element to negate.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_neg(pbcext_element_G2_t *dst, pbcext_element_G2_t *e);

  /** 
   * @fn int pbcext_element_Fr_inv(pbcext_element_Fr_inv_t *dst,
   *                               pbcext_element_Fr_inv_t *e)
   * @brief Sets dst to e^-1
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The element to invert.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_inv(pbcext_element_Fr_t *dst, pbcext_element_Fr_t *e);

  /** 
   * @fn int pbcext_element_Fp_inv(pbcext_element_Fp_t *dst,
   *                               pbcext_element_Fp_t *e)
   * @brief Sets dst to e^-1
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The element to invert
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_inv(pbcext_element_Fp_t *dst, pbcext_element_Fp_t *e);

  /** 
   * @fn int pbcext_element_GT_inv(pbcext_element_GT_t *dst,
   *                               pbcext_element_GT_t *e)
   * @brief Sets dst to e^-1
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The element to invert.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_inv(pbcext_element_GT_t *dst, pbcext_element_GT_t *e);

  /** 
   * @fn int pbcext_element_Fr_mul(pbcext_element_Fr_t *dst,
   *                               pbcext_element_Fr_t *e1,
   *                               pbcext_element_Fr_t *e2)
   * @brief Sets dst to e1*e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_mul(pbcext_element_Fr_t *dst,
			    pbcext_element_Fr_t *e1,
			    pbcext_element_Fr_t *e2);

  /** 
   * @fn int pbcext_element_Fp_mul(pbcext_element_Fp_t *dst,
   *                               pbcext_element_Fp_t *e1,
   *                               pbcext_element_Fp_t *e2)
   * @brief Sets dst to e1*e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_mul(pbcext_element_Fp_t *dst,
			    pbcext_element_Fp_t *e1,
			    pbcext_element_Fp_t *e2);

  /** 
   * @fn int pbcext_element_GT_mul(pbcext_element_GT_t *dst,
   *                               pbcext_element_GT_t *e1,
   *                               pbcext_element_GT_t *e2)
   * @brief Sets dst to e1*e2
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_mul(pbcext_element_GT_t *dst,
			    pbcext_element_GT_t *e1,
			    pbcext_element_GT_t *e2);

  /** 
   * @fn int pbcext_element_Fr_div(pbcext_element_Fr_t *dst,
   *                               pbcext_element_Fr_t *e1,
   *                               pbcext_element_Fr_t *e2)
   * @brief Sets dst to dividend/divisor.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] dividend The dividend.
   * @param[in] divisor The divisor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_div(pbcext_element_Fr_t *dst,
			    pbcext_element_Fr_t *dividend,
			    pbcext_element_Fr_t *divisor);

  /** 
   * @fn int pbcext_element_Fp_div(pbcext_element_Fp_t *dst,
   *                               pbcext_element_Fp_t *e1,
   *                               pbcext_element_Fp_t *e2)
   * @brief Sets dst to dividend/divisor.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] dividend The dividend.
   * @param[in] divisor The divisor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_div(pbcext_element_Fp_t *dst,
			    pbcext_element_Fp_t *dividend,
			    pbcext_element_Fp_t *divisor);

  /** 
   * @fn int pbcext_element_GT_div(pbcext_element_GT_t *dst,
   *                               pbcext_element_GT_t *e1,
   *                               pbcext_element_GT_t *e2)
   * @brief Sets dst to dividend/divisor.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] dividend The dividend.
   * @param[in] divisor The divisor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_div(pbcext_element_GT_t *dst,
			    pbcext_element_GT_t *dividend,
			    pbcext_element_GT_t *divisor);

  /** 
   * @fn int pbcext_element_G1_mul(pbcext_element_G1_t *dst,
   *                               pbcext_element_G1_t *e,
   *                               pbcext_element_Fr_t *s)
   * @brief Sets dst to s*e, where s is a scalar and e is a group element.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The group element.
   * @param[in] s The scalar.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_mul(pbcext_element_G1_t *dst,
			    pbcext_element_G1_t *e,
			    pbcext_element_Fr_t *s);

  /** 
   * @fn int pbcext_element_G2_mul(pbcext_element_G2_t *dst,
   *                               pbcext_element_G2_t *e,
   *                               pbcext_element_Fr_t *s)
   * @brief Sets dst to s*e, where s is a scalar and e is a group element.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The group element.
   * @param[in] s The scalar.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_mul(pbcext_element_G2_t *dst,
			    pbcext_element_G2_t *e,
			    pbcext_element_Fr_t *s);

  /** 
   * @fn int pbcext_element_GT_pow(pbcext_element_GT_t *dst,
   *                               pbcext_element_GT_t *e,
   *                               pbcext_element_Fr_t *s)
   * @brief Sets dst to e^s, where s is a scalar and e is a group element.
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e The group element.
   * @param[in] s The scalar.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_pow(pbcext_element_GT_t *dst,
			    pbcext_element_GT_t *base,
			    pbcext_element_Fr_t *exp);

  /** 
   * @fn int pbcext_pairing(pbcext_element_GT_t *dst,
   *                        pbcext_element_G1_t *e1,
   *                        pbcext_element_G2_t *e2)
   * @brief Sets dst to pairing(e1,e2).
   *
   * @param[in,out] dst The element to be set.
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_pairing(pbcext_element_GT_t *dst,
		     pbcext_element_G1_t *e1,
		     pbcext_element_G2_t *e2);

  /** 
   * @fn int pbcext_element_Fr_cmp(pbcext_element_Fr_t *e1,
   *                               pbcext_element_Fr_t *e2)
   * @brief Compares e1 and e2.
   *
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return 0 if e1==e2. != otherwise.
   */
  int pbcext_element_Fr_cmp(pbcext_element_Fr_t *e1, pbcext_element_Fr_t *e2);

  /** 
   * @fn int pbcext_element_Fp_cmp(pbcext_element_Fp_t *e1,
   *                               pbcext_element_Fp_t *e2)
   * @brief Compares e1 and e2.
   *
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return 0 if e1==e2. != otherwise.
   */
  int pbcext_element_Fp_cmp(pbcext_element_Fp_t *e1, pbcext_element_Fp_t *e2);

  /** 
   * @fn int pbcext_element_G1_cmp(pbcext_element_G1_t *e1,
   *                               pbcext_element_G1_t *e2)
   * @brief Compares e1 and e2.
   *
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return 0 if e1==e2. != otherwise.
   */
  int pbcext_element_G1_cmp(pbcext_element_G1_t *e1, pbcext_element_G1_t *e2);

  /** 
   * @fn int pbcext_element_G2_cmp(pbcext_element_G2_t *e1,
   *                               pbcext_element_G2_t *e2)
   * @brief Compares e1 and e2.
   *
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return 0 if e1==e2. != otherwise.
   */
  int pbcext_element_G2_cmp(pbcext_element_G2_t *e1, pbcext_element_G2_t *e2);

  /** 
   * @fn int pbcext_element_GT_cmp(pbcext_element_GT_t *e1,
   *                               pbcext_element_GT_t *e2)
   * @brief Compares e1 and e2.
   *
   * @param[in] e1 The first operand.
   * @param[in] e2 The second operand.
   * 
   * @return 0 if e1==e2. != otherwise.
   */
  int pbcext_element_GT_cmp(pbcext_element_GT_t *e1, pbcext_element_GT_t *e2);

  /** 
   * @fn int pbcext_element_Fr_is0(pbcext_element_Fr_t *e)
   * @brief Compares e with 0.
   *
   * @param[in] e The element to compare with 0.
   * 
   * @return 1 if e==0. 0 Otherwise.
   */
  int pbcext_element_Fr_is0(pbcext_element_Fr_t *e);

  /** 
   * @fn int pbcext_element_Fp_is0(pbcext_element_Fp_t *e)
   * @brief Compares e with 0.
   *
   * @param[in] e The element to compare with 0.
   * 
   * @return 1 if e==1. 0 Otherwise.
   */
  int pbcext_element_Fp_is0(pbcext_element_Fp_t *e);

  
  /** 
   * @fn int pbcext_element_Fr_is1(pbcext_element_Fr_t *e)
   * @brief Compares e with 1.
   *
   * @param[in] e The element to compare with 1.
   * 
   * @return 1 if e==1. 0 Otherwise.
   */
  int pbcext_element_Fr_is1(pbcext_element_Fr_t *e);

  /** 
   * @fn int pbcext_element_Fp_is1(pbcext_element_Fp_t *e)
   * @brief Compares e with 1.
   *
   * @param[in] e The element to compare with 1.
   * 
   * @return 1 if e==1. 0 Otherwise.
   */
  int pbcext_element_Fp_is1(pbcext_element_Fp_t *e);

  /** 
   * @fn int pbcext_element_G1_is0(pbcext_element_G1_t *e)
   * @brief Compares e with 0.
   *
   * @param[in] e The element to compare with 0.
   * 
   * @return 1 if e==0. 0 Otherwise.
   */
  int pbcext_element_G1_is0(pbcext_element_G1_t *e);

  /** 
   * @fn int pbcext_element_G2_is0(pbcext_element_G2_t *e)
   * @brief Compares e with 0.
   *
   * @param[in] e The element to compare with 0.
   * 
   * @return 1 if e==0. 0 Otherwise.
   */
  int pbcext_element_G2_is0(pbcext_element_G2_t *e);

  /** 
   * @fn int pbcext_element_GT_is0(pbcext_element_GT_t *e)
   * @brief Compares e with 0.
   *
   * @param[in] e The element to compare with 0.
   * 
   * @return 1 if e==0. 0 Otherwise.
   */
  int pbcext_element_GT_is0(pbcext_element_GT_t *e);
  
  /** 
   * @fn int pbcext_element_GT_is1(pbcext_element_GT_t *e)
   * @brief Compares e with 1.
   *
   * @param[in] e The element to compare with 1.
   * 
   * @return 1 if e==1. 0 Otherwise.
   */
  int pbcext_element_GT_is1(pbcext_element_GT_t *e);

  /**
   * @fn int pbcext_element_Fp_byte_size(uint64_t *size)
   * @brief Sets size the number of bytes required to represent an element in Fp.
   *
   * @param[in,out] size Will be set to the number of bytes required to represent 
   *  an element in Fp.
   *
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_byte_size(uint64_t *size);

  /**
   * @fn int pbcext_element_Fr_byte_size(uint64_t *size)
   * @brief Sets size the number of bytes required to represent an element in Fr.
   *
   * @param[in,out] size Will be set to the number of bytes required to represent 
   *  an element in Fr.
   *
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_byte_size(uint64_t *size);

  /**
   * @fn int pbcext_element_G1_byte_size(uint64_t *size)
   * @brief Sets size the number of bytes required to represent an element in G1.
   *
   * @param[in,out] size Will be set to the number of bytes required to represent 
   *  an element in G1.
   *
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_byte_size(uint64_t *size);

  /**
   * @fn int pbcext_element_G2_byte_size(uint64_t *size)
   * @brief Sets size the number of bytes required to represent an element in G2.
   *
   * @param[in,out] size Will be set to the number of bytes required to represent 
   *  an element in G2.
   *
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_byte_size(uint64_t *size);

  /**
   * @fn int pbcext_element_GT_byte_size(uint64_t *size)
   * @brief Sets size the number of bytes required to represent e.
   *
   * @param[in,out] size Will be set to the number of bytes required to represent
   *  e.
   *
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_byte_size(uint64_t *size);

  /** 
   * @fn int pbcext_element_Fr_to_bytes(byte_t **dst,
   *                                    uint64_t *len,
   *                                    pbcext_element_Fr_t *e)
   * @brief Exports e to a bytearray of len bytes.
   *
   * @param[in,out] dst The bytearray to store the element.
   * @param[in,out] len The allocated length, in bytes, of the array.
   * @param[in] e The element to export.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_to_bytes(byte_t **dst,
				 uint64_t *len,
				 pbcext_element_Fr_t *e);

  /** 
   * @fn int pbcext_element_Fp_to_bytes(byte_t **dst,
   *                                    uint64_t *len,
   *                                    pbcext_element_Fp_t *e)
   * @brief Exports e to a bytearray of len bytes.
   *
   * @param[in,out] dst The bytearray to store the element.
   * @param[in] len The allocated length, in bytes, of the array.
   * @param[in] e The element to export.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_to_bytes(byte_t **dst,
				 uint64_t *len,
				 pbcext_element_Fp_t *e);

  /** 
   * @fn int pbcext_element_G1_to_bytes(byte_t **dst,
   *                                    uint64_t *len,
   *                                    pbcext_element_G1_t *e)
   * @brief Exports e to a bytearray of len bytes.
   *
   * @param[in,out] dst The bytearray to store the element.
   * @param[in] len The allocated length, in bytes, of the array.
   * @param[in] e The element to export.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_to_bytes(byte_t **dst,
				 uint64_t *len,
				 pbcext_element_G1_t *e);

  /** 
   * @fn int pbcext_element_G2_to_bytes(byte_t **dst,
   *                                    uint64_t *len,
   *                                    pbcext_element_G2_t *e)
   * @brief Exports e to a bytearray of len bytes.
   *
   * @param[in,out] dst The bytearray to store the element.
   * @param[in] len The allocated length, in bytes, of the array.
   * @param[in] e The element to export.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_to_bytes(byte_t **dst,
				 uint64_t *len,
				 pbcext_element_G2_t *e);

  /**
   * @fn int pbcext_element_GT_to_bytes(byte_t **dst,
   *                                    uint64_t *len,
   *                                    pbcext_element_GT_t *e)
   * @brief Exports e to a bytearray of len bytes.
   *
   * @param[in,out] dst The bytearray to store the element.
   * @param[in] len The allocated length, in bytes, of the array.
   * @param[in] e The element to export.
   *
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_to_bytes(byte_t **dst,
				 uint64_t *len,
				 pbcext_element_GT_t *e);

  /** 
   * @fn int pbcext_element_Fr_from_bytes(pbcext_element_Fr_t *e,
   *                                      byte_t *src,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a bytearray of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] src The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_from_bytes(pbcext_element_Fr_t *e,
				   byte_t *src,
				   uint64_t len);

  /** 
   * @fn int pbcext_element_Fp_from_bytes(pbcext_element_Fp_t *e,
   *                                      byte_t *src,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a bytearray of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] src The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_from_bytes(pbcext_element_Fp_t *e,
				   byte_t *src,
				   uint64_t len);

  /** 
   * @fn int pbcext_element_G1_from_bytes(pbcext_element_G1_t *e,
   *                                      byte_t *src,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a bytearray of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] src The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_from_bytes(pbcext_element_G1_t *e,
				   byte_t *src,
				   uint64_t len);

  /** 
   * @fn int pbcext_element_G2_from_bytes(pbcext_element_G2_t *e,
   *                                      byte_t *src,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a bytearray of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] src The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_from_bytes(pbcext_element_G2_t *e,
				   byte_t *src,
				   uint64_t len);

  /** 
   * @fn int pbcext_element_GT_from_bytes(pbcext_element_GT_t *e,
   *                                      byte_t *src,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a bytearray of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] src The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_from_bytes(pbcext_element_GT_t *e,
				   byte_t *src,
				   uint64_t len);

  /** 
   * @fn int pbcext_element_Fr_from_unformat_bytes(pbcext_element_Fr_t *e,
   *                                               byte_t *src,
   *                                               uint64_t len)
   *                                      
   * @brief Imports into e the unformated bytes in src.
   *
   * @param[in,out] e The element to set.
   * @param[in] src The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_from_unformat_bytes(pbcext_element_Fr_t *e,
					    byte_t *src,
					    uint64_t len);

  /** 
   * @fn int pbcext_element_Fp_from_unformat_bytes(pbcext_element_Fp_t *e,
   *                                               byte_t *src,
   *                                               uint64_t len)
   *                                      
   * @brief Imports into e the unformated bytes in src.
   *
   * @param[in,out] e The element to set.
   * @param[in] src The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */  
  int pbcext_element_Fp_from_unformat_bytes(pbcext_element_Fp_t *e,
					    byte_t *src,
					    uint64_t len);
  
  /** 
   * @fn int pbcext_element_Fr_from_hash(pbcext_element_Fr_t *e,
   *                                      byte_t *h,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a hash (bytearray) of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] h The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_from_hash(pbcext_element_Fr_t *dst,
				  byte_t *h,
				  uint64_t len);

  /** 
   * @fn int pbcext_element_Fp_from_hash(pbcext_element_Fp_t *e,
   *                                      byte_t *h,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a hash (bytearray) of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] h The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_from_hash(pbcext_element_Fp_t *dst,
				  byte_t *h,
				  uint64_t len);

  /** 
   * @fn int pbcext_element_G1_from_hash(pbcext_element_G1_t *e,
   *                                      byte_t *h,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a hash (bytearray) of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] h The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_from_hash(pbcext_element_G1_t *dst,
				  byte_t *h,
				  uint64_t len);

  /** 
   * @fn int pbcext_element_G2_from_hash(pbcext_element_G2_t *e,
   *                                      byte_t *h,
   *                                      uint64_t len)
   *                                      
   * @brief Imports into e the element stored as a hash (bytearray) of len bytes.
   *
   * @param[in,out] e The element to set.
   * @param[in] h The bytearray containing the element to import.
   * @param[in] len The length in bytes of the byte array.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_from_hash(pbcext_element_G2_t *dst,
				  byte_t *h,
				  uint64_t len);

  /** 
   * @fn char* pbcext_element_Fr_to_b64(pbcext_element_Fr_t e)
   * @brief Converts the given element into a Base64 string.
   *
   * @param[in] e The element to convert.
   * 
   * @return A pointer to the produced Base64 string or NULL if error.
   */
  char* pbcext_element_Fr_to_b64(pbcext_element_Fr_t *e);

  /** 
   * @fn char* pbcext_element_Fp_to_b64(pbcext_element_Fp_t e)
   * @brief Converts the given element into a Base64 string.
   *
   * @param[in] e The element to convert.
   * 
   * @return A pointer to the produced Base64 string or NULL if error.
   */
  char* pbcext_element_Fp_to_b64(pbcext_element_Fp_t *e);

  /** 
   * @fn char* pbcext_element_G1_to_b64(pbcext_element_G1_t e)
   * @brief Converts the given element into a Base64 string.
   *
   * @param[in] e The element to convert.
   * 
   * @return A pointer to the produced Base64 string or NULL if error.
   */
  char* pbcext_element_G1_to_b64(pbcext_element_G1_t *e);

  /** 
   * @fn char* pbcext_element_G2_to_b64(pbcext_element_G2_t e)
   * @brief Converts the given element into a Base64 string.
   *
   * @param[in] e The element to convert.
   * 
   * @return A pointer to the produced Base64 string or NULL if error.
   */
  char* pbcext_element_G2_to_b64(pbcext_element_G2_t *e);

  /** 
   * @fn char* pbcext_element_GT_to_b64(pbcext_element_GT_t e)
   * @brief Converts the given element into a Base64 string.
   *
   * @param[in] e The element to convert.
   * 
   * @return A pointer to the produced Base64 string or NULL if error.
   */
  char* pbcext_element_GT_to_b64(pbcext_element_GT_t *e);

  /** 
   * @fn int pbcext_element_Fr_from_b64(pbcext_element_Fr_t *e, char *b64)
   * @brief Gets the element contained in the Base64 string <i>b64</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param b64 The string to parse.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_from_b64(pbcext_element_Fr_t *e, char *b64);

  /** 
   * @fn int pbcext_element_Fp_from_b64(pbcext_element_Fp_t *e, char *b64)
   * @brief Gets the element contained in the Base64 string <i>b64</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param b64 The string to parse.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fp_from_b64(pbcext_element_Fp_t *e, char *b64);

  /** 
   * @fn int pbcext_element_G1_from_b64(pbcext_element_G1_t *e, char *b64)
   * @brief Gets the element contained in the Base64 string <i>b64</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param b64 The string to parse.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_from_b64(pbcext_element_G1_t *e, char *b64);

  /** 
   * @fn int pbcext_element_G2_from_b64(pbcext_element_G2_t *e, char *b64)
   * @brief Gets the element contained in the Base64 string <i>b64</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param b64 The string to parse.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_from_b64(pbcext_element_G2_t *e, char *b64);

  /** 
   * @fn int pbcext_element_GT_from_b64(pbcext_element_GT_t *e, char *b64)
   * @brief Gets the element contained in the Base64 string <i>b64</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param b64 The string to parse.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_from_b64(pbcext_element_GT_t *e, char *b64);

  /** 
   * @fn int pbcext_dump_element_Fr_fd(pbcext_element_Fr_t *e, FILE *fd)
   * @brief Dumps element <i>e</i> into the specified file descriptor (at its
   *  current position) as binary data.
   *
   * Dumps the element into the current position of the received file descdriptor
   * prepending them by an int indicating the number of bytes of the element.
   *
   * @param[in] e The element to dump.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_Fr_fd(pbcext_element_Fr_t *e, FILE *fd);

  /** 
   * @fn int pbcext_dump_element_Fp_fd(pbcext_element_Fp_t *e, FILE *fd)
   * @brief Dumps element <i>e</i> into the specified file descriptor (at its
   *  current position) as binary data.
   *
   * Dumps the element into the current position of the received file descdriptor
   * prepending them by an int indicating the number of bytes of the element.
   *
   * @param[in] e The element to dump.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_Fp_fd(pbcext_element_Fp_t *e, FILE *fd);

  /** 
   * @fn int pbcext_dump_element_G1_fd(pbcext_element_G1_t e, FILE *fd)
   * @brief Dumps element <i>e</i> into the specified file descriptor (at its
   *  current position) as binary data.
   *
   * Dumps the element into the current position of the received file descdriptor
   * prepending them by an int indicating the number of bytes of the element.
   *
   * @param[in] e The element to dump.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_G1_fd(pbcext_element_G1_t *e, FILE *fd);

  /** 
   * @fn int pbcext_dump_element_G2_fd(pbcext_element_G2_t *e, FILE *fd)
   * @brief Dumps element <i>e</i> into the specified file descriptor (at its
   *  current position) as binary data.
   *
   * Dumps the element into the current position of the received file descdriptor
   * prepending them by an int indicating the number of bytes of the element.
   *
   * @param[in] e The element to dump.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_G2_fd(pbcext_element_G2_t *e, FILE *fd);

  /** 
   * @fn int pbcext_dump_element_GT_fd(pbcext_element_GT_t *e, FILE *fd)
   * @brief Dumps element <i>e</i> into the specified file descriptor (at its
   *  current position) as binary data.
   *
   * Dumps the element into the current position of the received file descdriptor
   * prepending them by an int indicating the number of bytes of the element.
   *
   * @param[in] e The element to dump.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_GT_fd(pbcext_element_GT_t *e, FILE *fd);

  /** 
   * @fn int pbcext_dump_element_Fr_bytes(byte_t **bytes, 
   *                                   uint64_t *written, 
   *                                   pbcext_element_Fr_t e*)
   * @brief Dumps the number of bytes of the given element (as an int), followed by 
   *  the element into the given byte array.
   *
   * @param[in,out] bytes The byte array to write into. Memory is internally 
   * allocated if *bytes is NULL.
   * @param[in,out] written Will be set to the number of bytes written into <i>bytes</i>.
   * @param[in] e The element to dump.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_Fr_bytes(byte_t **bytes,
				   uint64_t *written,
				   pbcext_element_Fr_t *e);

  /** 
   * @fn int pbcext_dump_element_Fp_bytes(byte_t **bytes, 
   *                                   uint64_t *written, 
   *                                   pbcext_element_Fp_t *e)
   * @brief Dumps the number of bytes of the given element (as an int), followed by 
   *  the element into the given byte array.
   *
   * @param[in,out] bytes The byte array to write into. Memory is internally 
   * allocated if *bytes is NULL.
   * @param[in,out] written Will be set to the number of bytes written into <i>bytes</i>.
   * @param[in] e The element to dump.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_Fp_bytes(byte_t **bytes,
				   uint64_t *written,
				   pbcext_element_Fp_t *e);

  /** 
   * @fn int pbcext_dump_element_G1_bytes(byte_t **bytes, 
   *                                   uint64_t *written, 
   *                                   pbcext_element_G1_t *e)
   * @brief Dumps the number of bytes of the given element (as an int), followed by 
   *  the element into the given byte array.
   *
   * @param[in,out] bytes The byte array to write into. Memory is internally 
   * allocated if *bytes is NULL.
   * @param[in,out] written Will be set to the number of bytes written into <i>bytes</i>.
   * @param[in] e The element to dump.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_G1_bytes(byte_t **bytes,
				   uint64_t *written,
				   pbcext_element_G1_t *e);

  /** 
   * @fn int pbcext_dump_element_G2_bytes(byte_t **bytes, 
   *                                   uint64_t *written, 
   *                                   pbcext_element_G2_t *e)
   * @brief Dumps the number of bytes of the given element (as an int), followed by 
   *  the element into the given byte array.
   *
   * @param[in,out] bytes The byte array to write into. Memory is internally 
   * allocated if *bytes is NULL.
   * @param[in,out] written Will be set to the number of bytes written into <i>bytes</i>.
   * @param[in] e The element to dump.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_G2_bytes(byte_t **bytes,
				   uint64_t *written,
				   pbcext_element_G2_t *e);

  /** 
   * @fn int pbcext_dump_element_GT_bytes(byte_t **bytes, 
   *                                   uint64_t *written, 
   *                                   pbcext_element_GT_t *e)
   * @brief Dumps the number of bytes of the given element (as an int), followed by 
   *  the element into the given byte array.
   *
   * @param[in,out] bytes The byte array to write into. Memory is internally 
   * allocated if *bytes is NULL.
   * @param[in,out] written Will be set to the number of bytes written into <i>bytes</i>.
   * @param[in] e The element to dump.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_dump_element_GT_bytes(byte_t **bytes,
				   uint64_t *written,
				   pbcext_element_GT_t *e);

  /** 
   * @fn int pbcext_get_element_fd(pbcext_element_Fr_t *e, bool *read, FILE *fd)
   * @brief Gets the element stored at the current position of the specified
   *  file descriptor.
   *
   * Reads the number of bytes the element occupies (contained in an int field)
   * and then reads exactly the same amount of bytes and loads them into an
   * element.
   *
   * @param[in,out] e Will be set to the received element.
   * @param[in,out] read Will be set to true if the element is read, to false 
   *  otherwise.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_Fr_fd(pbcext_element_Fr_t *e, bool *read, FILE *fd);

  /** 
   * @fn int pbcext_get_element_fd(pbcext_element_Fp_t *e, bool *read, FILE *fd)
   * @brief Gets the element stored at the current position of the specified
   *  file descriptor.
   *
   * Reads the number of bytes the element occupies (contained in an int field)
   * and then reads exactly the same amount of bytes and loads them into an
   * element.
   *
   * @param[in,out] e Will be set to the received element.
   * @param[in,out] read Will be set to true if the element is read, to false 
   *  otherwise.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_Fp_fd(pbcext_element_Fp_t *e, bool *read, FILE *fd);

  /** 
   * @fn int pbcext_get_element_fd(pbcext_element_G1_t *e, bool *read, FILE *fd)
   * @brief Gets the element stored at the current position of the specified
   *  file descriptor.
   *
   * Reads the number of bytes the element occupies (contained in an int field)
   * and then reads exactly the same amount of bytes and loads them into an
   * element.
   *
   * @param[in,out] e Will be set to the received element.
   * @param[in,out] read Will be set to true if the element is read, to false 
   *  otherwise.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_G1_fd(pbcext_element_G1_t *e, bool *read, FILE *fd);

  /** 
   * @fn int pbcext_get_element_fd(pbcext_element_G2_t *e, bool *read, FILE *fd)
   * @brief Gets the element stored at the current position of the specified
   *  file descriptor.
   *
   * Reads the number of bytes the element occupies (contained in an int field)
   * and then reads exactly the same amount of bytes and loads them into an
   * element.
   *
   * @param[in,out] e Will be set to the received element.
   * @param[in,out] read Will be set to true if the element is read, to false 
   *  otherwise.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_G2_fd(pbcext_element_G2_t *e, bool *read, FILE *fd);

  /** 
   * @fn int pbcext_get_element_fd(pbcext_element_GT_t *e, bool *read, FILE *fd)
   * @brief Gets the element stored at the current position of the specified
   *  file descriptor.
   *
   * Reads the number of bytes the element occupies (contained in an int field)
   * and then reads exactly the same amount of bytes and loads them into an
   * element.
   *
   * @param[in,out] e Will be set to the received element.
   * @param[in,out] read Will be set to true if the element is read, to false 
   *  otherwise.
   * @param[in] fd The file descriptor.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_GT_fd(pbcext_element_GT_t *e, bool *read, FILE *fd);

  /** 
   * @fn int pbcext_get_element_Fr_bytes(pbcext_element_Fr_t *e, 
   *                                     uint64_t *read, 
   *                                     byte_t *bytes)
   * @brief Gets an element encoded as specified in <i>pbcext_dump_element_bytes</i>
   * from the bytearray <i>bytes</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param[in,out] read Will be set to the number of bytes read, or 0 if only
   * the size header is read (to make easier to test whether an element was read).
   * @param[in] bytes Bytearray containing the element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_Fr_bytes(pbcext_element_Fr_t *e,
				  uint64_t *read,
				  byte_t *bytes);

  /** 
   * @fn int pbcext_get_element_Fp_bytes(pbcext_element_Fp_t *e, 
   *                                     uint64_t *read, 
   *                                     byte_t *bytes)
   * @brief Gets an element encoded as specified in <i>pbcext_dump_element_bytes</i>
   * from the bytearray <i>bytes</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param[in,out] read Will be set to the number of bytes read, or 0 if only
   * the size header is read (to make easier to test whether an element was read).
   * @param[in] bytes Bytearray containing the element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_Fp_bytes(pbcext_element_Fp_t *e,
				  uint64_t *read,
				  byte_t *bytes);

  /** 
   * @fn int pbcext_get_element_G1_bytes(pbcext_element_G1_t *e, 
   *                                     uint64_t *read, 
   *                                     byte_t *bytes)
   * @brief Gets an element encoded as specified in <i>pbcext_dump_element_bytes</i>
   * from the bytearray <i>bytes</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param[in,out] read Will be set to the number of bytes read, or 0 if only
   * the size header is read (to make easier to test whether an element was read).
   * @param[in] bytes Bytearray containing the element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_G1_bytes(pbcext_element_G1_t *e,
				  uint64_t *read,
				  byte_t *bytes);

  /** 
   * @fn int pbcext_get_element_G2_bytes(pbcext_element_G2_t *e, 
   *                                     uint64_t *read, 
   *                                     byte_t *bytes)
   * @brief Gets an element encoded as specified in <i>pbcext_dump_element_bytes</i>
   * from the bytearray <i>bytes</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param[in,out] read Will be set to the number of bytes read, or 0 if only
   * the size header is read (to make easier to test whether an element was read).
   * @param[in] bytes Bytearray containing the element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_G2_bytes(pbcext_element_G2_t *e,
				  uint64_t *read,
				  byte_t *bytes);

  /** 
   * @fn int pbcext_get_element_GT_bytes(pbcext_element_GT_t *e, 
   *                                     uint64_t *read, 
   *                                     byte_t *bytes)
   * @brief Gets an element encoded as specified in <i>pbcext_dump_element_bytes</i>
   * from the bytearray <i>bytes</i>.
   *
   * @param[in,out] e Will be set to the retrieved element.
   * @param[in,out] read Will be set to the number of bytes read, or 0 if only
   * the size header is read (to make easier to test whether an element was read).
   * @param[in] bytes Bytearray containing the element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_get_element_GT_bytes(pbcext_element_GT_t *e,
				  uint64_t *read,
				  byte_t *bytes);

  /** 
   * @fn int pbcext_element_Fr_to_string(char **str,
   *                                    uint64_t *len, 
   *                                    int base,   
   *                                    pbcext_element_Fr_t *e)
   * @brief Gets the string representation in base 16 of e.
   *
   * @param[in,out] str Will be set to the string representation of e.
   * @param[in,out] len Will be set to the length of str.
   * @param[in] base The base in which to represent e. 16 or 10.
   * @param[in] e The element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_Fr_to_string(char **str,
				  uint64_t *len,
				  int base,
				  pbcext_element_Fr_t *e);

  /** 
   * @fn int pbcext_element_G1_to_string(char **str,
   *                                    uint64_t *len, 
   *                                    int base,
   *                                    pbcext_element_G1_t *e)
   * @brief Gets the string representation in base 16 of e.
   *
   * @param[in,out] str Will be set to the string representation of e.
   * @param[in,out] len Will be set to the length of str.
   * @param[in] base The base in which to represent e. 16 or 10.
   * @param[in] e The element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G1_to_string(char **str,
				  uint64_t *len,
				  int base,
				  pbcext_element_G1_t *e);

  /** 
   * @fn int pbcext_element_G2_to_string(char **str,
   *                                    uint64_t *len, 
   *                                    int base,
   *                                    pbcext_element_G2_t *e)
   * @brief Gets the string representation in base 16 of e.
   *
   * @param[in,out] str Will be set to the string representation of e.
   * @param[in,out] len Will be set to the length of str.
   * @param[in] base The base in which to represent e. 16 or 10.
   * @param[in] e The element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_G2_to_string(char **str,
				  uint64_t *len,
				  int base,
				  pbcext_element_G2_t *e);

  /** 
   * @fn int pbcext_element_GT_to_string(char **str,
   *                                     uint64_t *len, 
   *                                     int base,
   *                                     pbcext_element_GT_t *e)
   * @brief Gets the string representation in base 16 of e.
   *
   * @param[in,out] str Will be set to the string representation of e.
   * @param[in,out] len Will be set to the length of str
.   * @param[in] base The base in which to represent e. 16 or 10.
   * @param[in] e The element.
   * 
   * @return IOK or IERROR.
   */
  int pbcext_element_GT_to_string(char **str,
				  uint64_t *len,
				  int base,
				  pbcext_element_GT_t *e);

  /** 
   * @fn int pbcext_element_Fr_from_string(pbcext_element_Fr_t **e, 
   *                                       char *str,
   *                                       int base);
   * @brief Sets e from the string in the given base.
   *
   * @param[in,out] e An initialized element. Will be set to the
   *  number represented in str. If *e is NULL, it will be internally
   *  allocated.
   * @param[in] str The string to get the number from.
   * @param[in] base The base in which str is represented. 16 or 10.
   * 
   * @return IOK or IERROR.
   */  
  int pbcext_element_Fr_from_string(pbcext_element_Fr_t **e,
				    char *str,
				    int base);

  /** 
   * @fn int pbcext_element_G1_from_string(pbcext_element_G1_t **e, 
   *                                       char *str,
   *                                       int base);
   * @brief Sets e from the string in the given base.
   *
   * @param[in,out] e An initialized element. Will be set to the
   *  number represented in str. If *e is NULL, it will be internally
   *  allocated.
   * @param[in] str The string to get the number from.
   * @param[in] base The base in which str is represented. 16 or 10.
   * 
   * @return IOK or IERROR.
   */  
  int pbcext_element_G1_from_string(pbcext_element_G1_t **e,
				    char *str,
				    int base);

  /** 
   * @fn int pbcext_element_G2_from_string(pbcext_element_G2_t **e, 
   *                                       char *str,
   *                                       int base);
   * @brief Sets e from the string in the given base.
   *
   * @param[in,out] e An initialized element. Will be set to the
   *  number represented in str. If *e is NULL, it will be internally
   *  allocated.
   * @param[in] str The string to get the number from.
   * @param[in] base The base in which str is represented. 16 or 10.
   * 
   * @return IOK or IERROR.
   */  
  int pbcext_element_G2_from_string(pbcext_element_G2_t **e,
				    char *str,
				    int base);
 
  /** 
   * @fn int pbcext_element_GT_from_string(pbcext_element_GT_t **e, 
   *                                       char *str,
   *                                       int base);
   * @brief Sets e from the string in the given base.
   *
   * @param[in,out] e An initialized element. Will be set to the
   *  number represented in str.If *e is NULL, it will be internally
   *  allocated.
   * @param[in] str The string to get the number from.
   * @param[in] base The base in which str is represented. 16 or 10.
   * 
   * @return IOK or IERROR.
   */  
  int pbcext_element_GT_from_string(pbcext_element_GT_t **e,
				    char *str,
				    int base); 


#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _PBC_EXT_H */

/* pbc_ext.h ends here */
