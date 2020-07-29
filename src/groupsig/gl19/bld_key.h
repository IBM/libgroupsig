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

#ifndef _GL19_BLD_KEY_H
#define _GL19_BLD_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "gl19.h"
#include "include/bld_key.h"
#include "shim/pbc_ext.h"

/**
 * @def GL19_BLD_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing GL19 blinding keys
 */
#define GL19_BLD_KEY_BEGIN_MSG "BEGIN GL19 BLINDING KEY"

/**
 * @def GL19_BLD_KEY_END_MSG
 * @brief End string to prepend to headers of files containing GL19 blinding keys
 */
#define GL19_BLD_KEY_END_MSG "END GL19 BLINDING KEY"

/**
 * @struct gl19_bld_key_t
 * @brief GL19 blinding keys. They are actually ElGamal encryption keys.
 */
typedef struct {
  pbcext_element_G1_t *pk; /**< Public key. Equals g^sk */
  pbcext_element_Fr_t *sk; /**< Randomly chosen private key. */
} gl19_bld_key_t;

/** 
 * @fn groupsig_key_t* gl19_bld_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* gl19_bld_key_init();

/** 
 * @fn int gl19_bld_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given blinding key.
 *
 * @param[in,out] key The blinding key to initialize.
 * 
 * @return IOK or IERROR
 */
int gl19_bld_key_free(groupsig_key_t *key);

/** 
 * @fn int gl19_bld_key_random(void *param)
 * @brief Initializes a new blinding key and sets it to a random value.
 *
 * @param[in] param Parameters needed for setup. In this case, the group
 *  key.
 * 
 * @return The randomly initialized blinding key, or NULL if error.
 */
groupsig_key_t* gl19_bld_key_random(void *param);

/** 
 * @fn int gl19_bld_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized 
 *  by the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int gl19_bld_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @fn int gl19_bld_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int gl19_bld_key_get_size(groupsig_key_t *key);

/** 
 * @fn int gl19_bld_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given blinding key to an array
 *  with format:
 *
 *  | GL19_CODE | KEYTYPE | size_pk | pk | size_sk | sk | 
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  blinding key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The blinding key to export.
 * 
 * @return IOK or IERROR.
 */
int gl19_bld_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn int gl19_bld_key_export_pub(groupsig_key_t *key, exim_format_t format,
 *                              void *dst)
 * @brief Exports the public part of the given blinding key, using the specified 
 * format, to the specified destination.
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  blinding key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The blinding key to export.
 * 
 * @return IOK or IERROR. 
 */
int gl19_bld_key_export_pub(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn int gl19_bld_key_export_prv(groupsig_key_t *key, exim_format_t format,
 *                                 void *dst)
 * @brief Exports the private part of the given blinding key, using the 
 * specified format, to the specified destination.
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  blinding key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The blinding key to export.
 * 
 * @return IOK or IERROR. 
 */
int gl19_bld_key_export_prv(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* gl19_bld_key_import(byte_t *source, uint32_t size)
 * @brief Imports a blinding key.
 *
 * Imports a GL19 blinding key from the specified source, of the specified format.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* gl19_bld_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* gl19_bld_key_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the specified blinding key.
 *
 * @param[in] key The blinding key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* gl19_bld_key_to_string(groupsig_key_t *key);

/**
 * @var gl19_bld_key_handle
 * @brief Set of functions for managing GL19 blinding keys.
 */
static const bld_key_handle_t gl19_bld_key_handle = {
 .code = GROUPSIG_GL19_CODE, /**< The scheme code. */
 .init = &gl19_bld_key_init, /**< Initializes blinding keys. */
 .free = &gl19_bld_key_free, /**< Frees blinding keys. */
 .random = &gl19_bld_key_random, /**< Randomly sets a blinding key. */
 .copy = &gl19_bld_key_copy, /**< Copies blinding keys. */
 .gexport = &gl19_bld_key_export, /**< Exports a full blinding key. */
 .gexport_pub = &gl19_bld_key_export_pub, /**< Exports the public part of a 
					   blinding key. */
 .gexport_prv = &gl19_bld_key_export_prv, /**< Exports the private part of a 
					   blinding key. */
 .gimport = &gl19_bld_key_import, /**< Imports a blinding key (public, private, or
				   full). */
 .to_string = &gl19_bld_key_to_string, /**< Converts blinding keys to printable 
					strings. */
 .get_size = &gl19_bld_key_get_size, /**< Gets the size of the key. */
};

#endif /* _GL19_BLD_KEY_H */

/* bld_key.h ends here */
