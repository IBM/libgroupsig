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

#ifndef _CPY06_GRP_KEY_H
#define _CPY06_GRP_KEY_H

#include <stdint.h>
#include <pbc/pbc.h>
#include "types.h"
#include "sysenv.h"
#include "cpy06.h"
#include "include/grp_key.h"

/**
 * @struct cpy06_grp_key_t
 * @brief Structure for CPY06 group keys.
 *
 * CPY06 group keys. 
 */
typedef struct {
  element_t g1; /**< Tr(g2) */
  element_t g2; /**< Random generator of G2 */
  element_t q; /**< Q \in_R G1 */
  element_t r; /**< R = g2^\gamma */
  element_t w; /**< W \in_R G2 \setminus 1 */
  element_t x; /**< X = Z^(\xi_1^-1) */
  element_t y; /**< Y = Z^(\xi_2^-1) */
  element_t z; /**< Z \in_R G1 \setminus 1 */
  /* Optimizations */
  element_t T5; /**< T5 = e(g1, W). Used in sign. */
  element_t e2; /**< e2 = e(z,g2). Used in sign. */
  element_t e3; /**< e3 = e(z,r). Used in sign. */
  element_t e4; /**< e4 = e(g1,g2). Used in sign. */
  element_t e5; /**< e5 = e(q,g2). Used in verify. */
} cpy06_grp_key_t;

/**
 * @def CPY06_GRP_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing CPY06 group keys
 */
#define CPY06_GRP_KEY_BEGIN_MSG "BEGIN CPY06 GROUPKEY"

/**
 * @def CPY06_GRP_KEY_END_MSG
 * @brief End string to prepend to headers of files containing CPY06 group keys
 */
#define CPY06_GRP_KEY_END_MSG "END CPY06 GROUPKEY"

/** 
 * @fn groupsig_key_t* cpy06_grp_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* cpy06_grp_key_init();

/** 
 * @fn int cpy06_grp_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given group key.
 *
 * @param[in,out] key The group key to initialize.
 * 
 * @return IOK or IERROR
 */
int cpy06_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int cpy06_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
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
int cpy06_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @fn int cpy06_grp_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format)
 * @brief Returns the size that the given key would require in order to be
 *  represented using the specified format.
 *
 * @param[in] key The key.
 * @param[in] format The format. The list of supported key formats in the CPY06
 *  scheme are defined in @ref cpy06.h.
 *
 * @return The required number of bytes, or -1 if error.
 */
int cpy06_grp_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format);

/** 
 * @fn int cpy06_grp_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst)
 * @brief Exports the given group key.
 *
 * Exports the given CPY06 group key, to the specified destination, using the given format.
 *
 * @param[in] key The group key to export.
 * @param[in] format The format to use for exporting the key. The available key 
 *  formats in CPY06 are defined in @ref cpy06.h.
 * @param[in] dst The destination's description.
 * 
 * @return IOK or IERROR.
 */
int cpy06_grp_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst);

/** 
 * @fn groupsig_key_t* cpy06_grp_key_import(groupsig_key_format_t format, void *source)
 * @brief Imports a group key.
 *
 * Imports a CPY06 group key from the specified source, of the specified format.
 * 
 * @param[in] format The source format. The available key formats in CPY06 are
 *  defined in @ref cpy06.h.
 * @param[in] source The source's description.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* cpy06_grp_key_import(groupsig_key_format_t format, void *source);

/** 
 * @fn char* cpy06_grp_key_to_string(groupsig_key_t *key)
 * @brief Converts the key to a printable string.
 *
 * Returns a printable string associated to the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return The printable string associated to the key, or NULL if error.
 */
char* cpy06_grp_key_to_string(groupsig_key_t *key);

/**
 * @var cpy06_grp_key_handle
 * @brief The set of functions to manage CPY06 group keys.
 */
static const grp_key_handle_t cpy06_grp_key_handle = {
  GROUPSIG_CPY06_CODE, /**< Scheme. */
  &cpy06_grp_key_init, /**< Initialize group keys. */
  &cpy06_grp_key_free, /**< Free group keys. */
  &cpy06_grp_key_copy, /**< Copy group keys. */
  &cpy06_grp_key_export, /**< Export group keys. */
  &cpy06_grp_key_import, /**< Import group keys. */
  &cpy06_grp_key_to_string, /**< Convert to printable strings. */
  &cpy06_grp_key_get_size_in_format,
};

#endif

/* grp_key.h ends here */
