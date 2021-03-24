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

#ifndef _GL19_GRP_KEY_H
#define _GL19_GRP_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "gl19.h"
#include "include/grp_key.h"
#include "shim/pbc_ext.h"
/**
 * @struct gl19_grp_key_t
 * @brief Structure for GL19 group keys.
 *
 * For convenience, we set a public key of GL19 to contain the instance parameters 
 * as well as the public keys of Issuer and Converter. @TODO We may want to 
 * redesign this at some point...
 */
typedef struct {
  pbcext_element_G1_t *g1; /**< Params. Random generator of G1. */
  pbcext_element_G2_t *g2; /**< Params. Random generator of G2. */
  pbcext_element_G1_t *g; /**< Params. Random generator of G1. */
  pbcext_element_G1_t *h; /**< Params. Random generator of G1. */
  pbcext_element_G1_t *h1; /**< Params. Random generator of G1. */
  pbcext_element_G1_t *h2; /**< Params. Random generator of G1. */
  pbcext_element_G1_t *h3; /**< Params. Random generator of G1. 
			      Used for setting expiration date of
			      member creds. */
  pbcext_element_G2_t *ipk; /**< Issuer public key. */
  pbcext_element_G1_t *cpk; /**< Converter public key. */
  pbcext_element_G1_t *epk; /**< Extractor public key. */
} gl19_grp_key_t;

/**
 * @def GL19_GRP_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing GL19 group keys
 */
#define GL19_GRP_KEY_BEGIN_MSG "BEGIN GL19 GROUPKEY"

/**
 * @def GL19_GRP_KEY_END_MSG
 * @brief End string to prepend to headers of files containing GL19 group keys
 */
#define GL19_GRP_KEY_END_MSG "END GL19 GROUPKEY"

/** 
 * @fn groupsig_key_t* gl19_grp_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* gl19_grp_key_init();

/** 
 * @fn int gl19_grp_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given group key.
 *
 * @param[in,out] key The group key to initialize.
 * 
 * @return IOK or IERROR
 */
int gl19_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int gl19_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
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
int gl19_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @fn int gl19_grp_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int gl19_grp_key_get_size(groupsig_key_t *key);

/** 
 * @fn int gl19_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given group key to an array
 *  with format:
 *
 *  | GL19_CODE | KEYTYPE | size_g1 | g1 | size_g2 | g2 |
 *    size_g | g | size_h | h | size_h1 | h1 | size_h2 | h2 | size_h3 | h3 |
 *    size_ipk | ipk | size_cpk | cpk | size_epk | epk |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  group key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The group key to export.
 * 
 * @return IOK or IERROR.
 */
int gl19_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* gl19_grp_key_import(byte_t *source, uint32_t size)
 * @brief Imports a group key.
 *
 * Imports a GL19 group key from the specified array of bytes.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* gl19_grp_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* gl19_grp_key_to_string(groupsig_key_t *key)
 * @brief Converts the key to a printable string.
 *
 * Returns a printable string associated to the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return The printable string associated to the key, or NULL if error.
 */
char* gl19_grp_key_to_string(groupsig_key_t *key);

/**
 * @var gl19_grp_key_handle
 * @brief The set of functions to manage GL19 group keys.
 */
static const grp_key_handle_t gl19_grp_key_handle = {
  .code = GROUPSIG_GL19_CODE, /**< Scheme. */
  .init = &gl19_grp_key_init, /**< Initialize group keys. */
  .free = &gl19_grp_key_free, /**< Free group keys. */
  .copy = &gl19_grp_key_copy, /**< Copy group keys. */
  .gexport = &gl19_grp_key_export, /**< Export group keys. */
  .gimport = &gl19_grp_key_import, /**< Import group keys. */
  .to_string = &gl19_grp_key_to_string, /**< Convert to printable strings. */
  .get_size = &gl19_grp_key_get_size, /**< Get size of key as bytes. */
};

#endif

/* grp_key.h ends here */
