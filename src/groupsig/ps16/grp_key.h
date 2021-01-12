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

#ifndef _PS16_GRP_KEY_H
#define _PS16_GRP_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "ps16.h"
#include "include/grp_key.h"
#include "shim/pbc_ext.h"

/**
 * @struct ps16_grp_key_t
 * @brief Structure for PS16 group keys.
 *
 * PS16 group keys. 
 */
typedef struct {
  pbcext_element_G1_t *g; /**< Random generator of G1 */
  pbcext_element_G2_t *gg; /**< Random generator of G2 */
  pbcext_element_G2_t *X; /**< gg^x (x is part of mgrkey) */
  pbcext_element_G2_t *Y;  /**< gg^y (y is part of mgrkey) */
} ps16_grp_key_t;

/**
 * @def PS16_GRP_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing PS16 group keys
 */
#define PS16_GRP_KEY_BEGIN_MSG "BEGIN PS16 GROUPKEY"

/**
 * @def PS16_GRP_KEY_END_MSG
 * @brief End string to prepend to headers of files containing PS16 group keys
 */
#define PS16_GRP_KEY_END_MSG "END PS16 GROUPKEY"

/** 
 * @fn groupsig_key_t* ps16_grp_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* ps16_grp_key_init();

/** 
 * @fn int ps16_grp_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given group key.
 *
 * @param[in,out] key The group key to initialize.
 * 
 * @return IOK or IERROR
 */
int ps16_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int ps16_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
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
int ps16_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int ps16_grp_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int ps16_grp_key_get_size(groupsig_key_t *key);

/**
 * @fn int ps16_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given key, with format:
 *
 *  | PS16_CODE | KEYTYPE | size_g | g | size_gg | gg | size_X | X | size_Y | Y |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  group key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The group key to export.
 *
 * @return IOK or IERROR
 */
int ps16_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* ps16_grp_key_import(byte_t *source, uint32_t size)
 * @brief Imports a group key.
 *
 * Imports a PS16 group key from the specified array of bytes.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* ps16_grp_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* ps16_grp_key_to_string(groupsig_key_t *key)
 * @brief Converts the key to a printable string.
 *
 * Returns a printable string associated to the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return The printable string associated to the key, or NULL if error.
 */
char* ps16_grp_key_to_string(groupsig_key_t *key);

/**
 * @var ps16_grp_key_handle
 * @brief The set of functions to manage PS16 group keys.
 */
static const grp_key_handle_t ps16_grp_key_handle = {
  .code = GROUPSIG_PS16_CODE, /**< Scheme. */
  .init = &ps16_grp_key_init, /**< Initialize group keys. */
  .free = &ps16_grp_key_free, /**< Free group keys. */
  .copy = &ps16_grp_key_copy, /**< Copy group keys. */
  .gexport = &ps16_grp_key_export, /**< Export group keys. */
  .gimport = &ps16_grp_key_import, /**< Import group keys. */
  .to_string = &ps16_grp_key_to_string, /**< Convert to printable strings. */
  .get_size = &ps16_grp_key_get_size,
};

#endif

/* grp_key.h ends here */
