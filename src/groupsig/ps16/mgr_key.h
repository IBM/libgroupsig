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

#ifndef _PS16_MGR_KEY_H
#define _PS16_MGR_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "ps16.h"
#include "include/mgr_key.h"
#include "shim/pbc_ext.h"

/**
 * @def PS16_MGR_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing PS16 group keys
 */
#define PS16_MGR_KEY_BEGIN_MSG "BEGIN PS16 MANAGERKEY"

/**
 * @def PS16_MGR_KEY_END_MSG
 * @brief End string to prepend to headers of files containing PS16 group keys
 */
#define PS16_MGR_KEY_END_MSG "END PS16 MANAGERKEY"

/**
 * @struct ps16_mgr_key_t
 * @brief PS16 manager key. 
 */
typedef struct {
  pbcext_element_Fr_t *x; 
  pbcext_element_Fr_t *y; 
} ps16_mgr_key_t;

/** 
 * @fn groupsig_key_t* ps16_mgr_key_init()
 * @brief Creates a new PS16 manager key
 *
 * @return The created manager key or NULL if error.
 */
groupsig_key_t* ps16_mgr_key_init();

/** 
 * @fn int ps16_mgr_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given manager key.
 *
 * @param[in,out] key The manager key to initialize.
 * 
 * @return IOK or IERROR
 */
int ps16_mgr_key_free(groupsig_key_t *key);

/** 
 * @fn int ps16_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int ps16_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int ps16_mgr_key_get_size(groupsig_key_t *key)
 * @brief Returns the size that the given key would require in order to be
 *  stored in an array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int ps16_mgr_key_get_size(groupsig_key_t *key);

/**
 * @fn int ps16_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given key, with format:
 *
 *  | PS16_CODE | KEYTYPE | size_x | x | size_y | y |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  manager key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The manager key to export.
 *
 * @return IOK or IERROR
 */
int ps16_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* ps16_mgr_key_import(byte_t *source, uint32_t size)
 * @brief Imports a manager key.
 *
 * Imports a PS16 manager key from the specified array of bytes.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* ps16_mgr_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* ps16_mgr_key_to_string(mgr_key_t *key)
 * @brief Creates a printable string of the given manager key.
 *
 * @param[in] key The manager key.
 * 
 * @return The created string or NULL if error.
 */
char* ps16_mgr_key_to_string(groupsig_key_t *key);

/**
 * @var ps16_mgr_key_handle
 * @brief Set of functions for PS16 manager keys management.
 */
static const mgr_key_handle_t ps16_mgr_key_handle = {
  .code = GROUPSIG_PS16_CODE, /**< The scheme code. */
  .init = &ps16_mgr_key_init, /**< Initializes manager keys. */
  .free = &ps16_mgr_key_free, /**< Frees manager keys. */
  .copy = &ps16_mgr_key_copy, /**< Copies manager keys. */
  .gexport = &ps16_mgr_key_export, /**< Exports manager keys. */
  .gimport = &ps16_mgr_key_import, /**< Imports manager keys. */
  .to_string = &ps16_mgr_key_to_string, /**< Converts manager keys to printable strings. */
  .get_size = &ps16_mgr_key_get_size,
};

#endif

/* mgr_key.h ends here */
