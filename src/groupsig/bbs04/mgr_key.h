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

#ifndef _BBS04_MGR_KEY_H
#define _BBS04_MGR_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "bbs04.h"
#include "include/mgr_key.h"
#include "shim/pbc_ext.h"

/**
 * @def BBS04_MGR_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing BBS04 group keys
 */
#define BBS04_MGR_KEY_BEGIN_MSG "BEGIN BBS04 MANAGERKEY"

/**
 * @def BBS04_MGR_KEY_END_MSG
 * @brief End string to prepend to headers of files containing BBS04 group keys
 */
#define BBS04_MGR_KEY_END_MSG "END BBS04 MANAGERKEY"

/**
 * @struct bbs04_mgr_key_t
 * @brief BBS04 manager key. 
 * 
 * In the BBS04 paper, the private key issuer role (the owner of the gamma field
 * below) is differentiated from that of the group manager (who can revoke members).
 * However, we combine both roles into the group manager, for simplicity.
 */
typedef struct {
  pbcext_element_Fr_t *xi1; /**< Exponent for tracing signatures. */
  pbcext_element_Fr_t *xi2; /**< Exponent for tracing signatures. */
  pbcext_element_Fr_t *gamma; /**< Exponent for generating member keys. */
} bbs04_mgr_key_t;

/** 
 * @fn groupsig_key_t* bbs04_mgr_key_init()
 * @brief Creates a new BBS04 manager key
 *
 * @return The created manager key or NULL if error.
 */
groupsig_key_t* bbs04_mgr_key_init();

/** 
 * @fn int bbs04_mgr_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given manager key.
 *
 * @param[in,out] key The manager key to initialize.
 * 
 * @return IOK or IERROR
 */
int bbs04_mgr_key_free(groupsig_key_t *key);

/** 
 * @fn int bbs04_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int bbs04_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int bbs04_mgr_key_get_size(groupsig_key_t *key)
 * @brief Returns the size that the given key would require in order to be
 *  stored in an array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int bbs04_mgr_key_get_size(groupsig_key_t *key);

/**
 * @fn int bbs04_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given key, with format:
 *
 *  | BBS04_CODE | KEYTYPE | size_xi1 | xi1 | size_xi2 | xi2 | size_gamma | gamma |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  manager key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The manager key to export.
 *
 * @return IOK or IERROR
 */
int bbs04_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* bbs04_mgr_key_import(byte_t *source, uint32_t size)
 * @brief Imports a manager key.
 *
 * Imports a BBS04 manager key from the specified array of bytes.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* bbs04_mgr_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* bbs04_mgr_key_to_string(mgr_key_t *key)
 * @brief Creates a printable string of the given manager key.
 *
 * @param[in] key The manager key.
 * 
 * @return The created string or NULL if error.
 */
char* bbs04_mgr_key_to_string(groupsig_key_t *key);

/**
 * @var bbs04_mgr_key_handle
 * @brief Set of functions for BBS04 manager keys management.
 */
static const mgr_key_handle_t bbs04_mgr_key_handle = {
  .code = GROUPSIG_BBS04_CODE, /**< The scheme code. */
  .init = &bbs04_mgr_key_init, /**< Initializes manager keys. */
  .free = &bbs04_mgr_key_free, /**< Frees manager keys. */
  .copy = &bbs04_mgr_key_copy, /**< Copies manager keys. */
  .gexport = &bbs04_mgr_key_export, /**< Exports manager keys. */
  .gimport = &bbs04_mgr_key_import, /**< Imports manager keys. */
  .to_string = &bbs04_mgr_key_to_string, /**< Converts manager keys to printable strings. */
  .get_size = &bbs04_mgr_key_get_size,
};

#endif

/* mgr_key.h ends here */
