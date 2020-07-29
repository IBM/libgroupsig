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

#ifndef _BBS04_GRP_KEY_H
#define _BBS04_GRP_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "bbs04.h"
#include "include/grp_key.h"
#include "shim/pbc_ext.h"

/**
 * @struct bbs04_grp_key_t
 * @brief Structure for BBS04 group keys.
 *
 * BBS04 group keys. 
 */
typedef struct {
  pbcext_element_G1_t *g1; /**< Tr(g2) */
  pbcext_element_G2_t *g2; /**< Random generator of G2 */
  pbcext_element_G1_t *h; /**< Random element in G1 \ 1 */
  pbcext_element_G1_t *u; /**< h^(xi1^-1) @see bbs04_mgr_key_t */
  pbcext_element_G1_t *v; /**< h^(xi2^-1) @see bbs04_mgr_key_t */
  pbcext_element_G2_t *w; /**< g2^gamma @see bbs04_mgr_key_t */
  pbcext_element_GT_t *hw; /**< Precompute e(h,w) **/
  pbcext_element_GT_t *hg2; /**<Precompute e(h,g2) **/
  pbcext_element_GT_t *g1g2; /**< Precompute e(g1,g2) **/
} bbs04_grp_key_t;

/**
 * @def BBS04_GRP_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing BBS04 group keys
 */
#define BBS04_GRP_KEY_BEGIN_MSG "BEGIN BBS04 GROUPKEY"

/**
 * @def BBS04_GRP_KEY_END_MSG
 * @brief End string to prepend to headers of files containing BBS04 group keys
 */
#define BBS04_GRP_KEY_END_MSG "END BBS04 GROUPKEY"

/** 
 * @fn groupsig_key_t* bbs04_grp_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* bbs04_grp_key_init();

/** 
 * @fn int bbs04_grp_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given group key.
 *
 * @param[in,out] key The group key to initialize.
 * 
 * @return IOK or IERROR
 */
int bbs04_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int bbs04_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies a group key.
 *
 * Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int bbs04_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int bbs04_grp_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int bbs04_grp_key_get_size(groupsig_key_t *key);

/**
 * @fn int bbs04_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given key, with format:
 *
 *  | BBS04_CODE | KEYTYPE | size_g1 | g1 | size_g2 | g2 | size_h | h |
 *    size_u | u | size_v | v |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  group key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The group key to export.
 *
 * @return IOK or IERROR
 */
int bbs04_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* bbs04_grp_key_import(byte_t *source, uint32_t size)
 * @brief Imports a group key.
 *
 * Imports a BBS04 group key from the specified array of bytes.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* bbs04_grp_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* bbs04_grp_key_to_string(groupsig_key_t *key)
 * @brief Converts the key to a printable string.
 *
 * Returns a printable string associated to the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return The printable string associated to the key, or NULL if error.
 */
char* bbs04_grp_key_to_string(groupsig_key_t *key);

/**
 * @var bbs04_grp_key_handle
 * @brief The set of functions to manage BBS04 group keys.
 */
static const grp_key_handle_t bbs04_grp_key_handle = {
  .code = GROUPSIG_BBS04_CODE, /**< Scheme. */
  .init = &bbs04_grp_key_init, /**< Initialize group keys. */
  .free = &bbs04_grp_key_free, /**< Free group keys. */
  .copy = &bbs04_grp_key_copy, /**< Copy group keys. */
  .gexport = &bbs04_grp_key_export, /**< Export group keys. */
  .gimport = &bbs04_grp_key_import, /**< Import group keys. */
  .to_string = &bbs04_grp_key_to_string, /**< Convert to printable strings. */
  .get_size = &bbs04_grp_key_get_size,
};

#endif

/* grp_key.h ends here */
