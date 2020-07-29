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

#ifndef _GL19_MEM_KEY_H
#define _GL19_MEM_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "gl19.h"
#include "include/mem_key.h"
#include "crypto/spk.h"

/**
 * @def GL19_MEM_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing GL19 member keys
 */
#define GL19_MEM_KEY_BEGIN_MSG "BEGIN GL19 MEMBERKEY"

/**
 * @def GL19_MEM_KEY_END_MSG
 * @brief End string to prepend to headers of files containing GL19 member keys
 */
#define GL19_MEM_KEY_END_MSG "END GL19 MEMBERKEY"

/**
 * @struct gl19_mem_key_t
 * @brief GL19 member keys.
 */
typedef struct {
  pbcext_element_G1_t *A; /**< A = (H*h2^s*g1)^(1/isk+x) */
  pbcext_element_Fr_t *x; /**< Randomly picked by the Issuer. */
  pbcext_element_Fr_t *y; /**< Randomly picked by the Member. */
  pbcext_element_Fr_t *s; /**< Randomly picked by the Issuer. */
  /* Precomputations */
  pbcext_element_G1_t *H; /**< Member's "public key". H = h1^y. */
  pbcext_element_G1_t *h2s; /**< Used in signatures. h2s = h2^s. */
  /* @TODO Stuff that should not be here, but I leave it be for the moment... */
  /* spk_dlog_t *pi; /\**< SPK sent in the second message. No need to store this. *\/ */
  /* element_t n; /\**< Random number (should be chosen by the Issuer...) No need to store this. *\/ */
} gl19_mem_key_t;

/** 
 * @fn groupsig_key_t* gl19_mem_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* gl19_mem_key_init();

/** 
 * @fn int gl19_mem_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given member key.
 *
 * @param[in,out] key The member key to initialize.
 * 
 * @return IOK or IERROR
 */
int gl19_mem_key_free(groupsig_key_t *key);

/** 
 * @fn int gl19_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized 
 *  by the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int gl19_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @fn int gl19_mem_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int gl19_mem_key_get_size(groupsig_key_t *key);

/** 
 * @fn int gl19_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given member key to an array
 *  with format:
 *
 *  | GL19_CODE | KEYTYPE | size_A | A | size_x | x | 
 *    size_y | y | size_s | s | size_H | H | size_h2s | h2s |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  member key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The member key to export.
 * 
 * @return IOK or IERROR.
 */
int gl19_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* gl19_mem_key_import(byte_t *source, uint32_t size)
 * @brief Imports a member key.
 *
 * Imports a GL19 member key from the specified source, of the specified format.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* gl19_mem_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* gl19_mem_key_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the specified member key.
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* gl19_mem_key_to_string(groupsig_key_t *key);

/**
 * @var gl19_mem_key_handle
 * @brief Set of functions for managing GL19 member keys.
 */
static const mem_key_handle_t gl19_mem_key_handle = {
  .code = GROUPSIG_GL19_CODE, /**< The scheme code. */
  .init = &gl19_mem_key_init, /**< Initializes member keys. */
  .free = &gl19_mem_key_free, /**< Frees member keys. */
  .copy = &gl19_mem_key_copy, /**< Copies member keys. */
  .get_size = &gl19_mem_key_get_size, /**< Gets the size of the key. */
  .gexport = &gl19_mem_key_export, /**< Exports member keys. */
  .gimport = &gl19_mem_key_import, /**< Imports member keys. */
  .to_string = &gl19_mem_key_to_string, /**< Converts member keys to printable strings. */
};

#endif /* _GL19_MEM_KEY_H */

/* mem_key.h ends here */
