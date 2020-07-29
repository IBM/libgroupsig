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

#ifndef _KTY04_MGR_KEY_H
#define _KTY04_MGR_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "groupsig/kty04/sphere.h"
#include "kty04.h"
#include "include/mgr_key.h"

/**
 * @def KTY04_MGR_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing KTY04 group keys
 */
#define KTY04_MGR_KEY_BEGIN_MSG "BEGIN KTY04 MANAGERKEY"

/**
 * @def KTY04_MGR_KEY_END_MSG
 * @brief End string to prepend to headers of files containing KTY04 group keys
 */
#define KTY04_MGR_KEY_END_MSG "END KTY04 MANAGERKEY"

/**
 * @struct kty04_mgr_key_t
 * @brief Defines the manager keys of the KTY04 scheme. The n component of the associated
 *  public key must satisfy n = p*q.
 */
typedef struct {
  bigz_t p; /**< The p safe prime */
  bigz_t q; /**< The q safe prime*/
  bigz_t x; /**< Used as open trapdoor. NOTE: there is an errata in the article
	       and this variable is not mentioned (email from Vicente Benjumea). It
	       must be chosen randomly from M, and y=g^x (mod n). */
  uint64_t nu; /**< The parameter defining the spheres. This is not private, really,
		  but will save us some computing... */
} kty04_mgr_key_t;

/** 
 * @fn groupsig_key_t* kty04_mgr_key_init()
 * @brief Creates a new KTY04 manager key
 *
 * @return The created manager key or NULL if error.
 */
groupsig_key_t* kty04_mgr_key_init();

/** 
 * @fn int kty04_mgr_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given manager key.
 *
 * @param[in,out] key The manager key to initialize.
 * 
 * @return IOK or IERROR
 */
int kty04_mgr_key_free(groupsig_key_t *key);

/** 
 * @fn int kty04_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int kty04_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/* groupsig_key_t* kty04_mgr_key_get_prv(groupsig_key_t *key); */
/* groupsig_key_t* kty04_mgr_key_get_pub(groupsig_key_t *key); */
/* int kty04_mgr_key_set_prv(void *dst, void *src); */
/* int kty04_mgr_key_set_pub(void *dst, void *src); */

/**
 * @fn int kty04_mgr_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format)
 * @brief Returns the size that the given key would require in order to be
 *  represented using the specified format.
 *
 * @param[in] key The key.
 * @param[in] format The format. The list of supported key formats in the KTY04
 *  scheme are defined in @ref kty04.h.
 *
 * @return The required number of bytes, or -1 if error.
 */
int kty04_mgr_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format);

/** 
 * @fn int kty04_mgr_key_export(groupsig_key_t *key, groupsig_key_format_t format, 
 *                              void *dst)
 * @brief Exports the given manager key to the specified destination, using the
 *  specified format.
 *
 * @param[in] key The key to export.
 * @param[in] format The format to use. The supported formats for KTY04 keys are
 *  specified in @ref kty04.h.
 * @param[in] dst The destination information.
 * 
 * @return IOK or IERROR.
 */
int kty04_mgr_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst);
/* int kty04_mgr_key_export_pub(groupsig_key_t *key, groupsig_key_format_t format, void *dst); */
/* int kty04_mgr_key_export_prv(groupsig_key_t *key, groupsig_key_format_t format, void *dst); */

/** 
 * @fn groupsig_key_t* kty04_mgr_key_import(groupsig_key_format_t format, 
 *                                          void *source)
 * @brief Imports a KTY04 manager key from the specified source, of the specified
 *  format.

 * @param[in] format The format of <i>source</i>. The supported formats for KTY04
 *  keys are defined in @ref kty04.h.
 * @param[in] source The source information.
 * 
 * @return A pointer to the imported manager key, or NULL if error.
 */
groupsig_key_t* kty04_mgr_key_import(groupsig_key_format_t format, void *source);
/* groupsig_key_t* kty04_mgr_key_import_prv(groupsig_key_format_t format, void *source); */
/* groupsig_key_t* kty04_mgr_key_import_pub(groupsig_key_format_t format, void *source); */

/** 
 * @fn char* kty04_mgr_key_to_string(mgr_key_t *key)
 * @brief Creates a printable string of the given manager key.
 *
 * @param[in] key The manager key.
 * 
 * @return The created string or NULL if error.
 */
char* kty04_mgr_key_to_string(groupsig_key_t *key);

/* char* kty04_mgr_key_prv_to_string(groupsig_key_t *key); */
/* char* kty04_mgr_key_pub_to_string(groupsig_key_t *key); */

/**
 * @var kty04_mgr_key_handle
 * @brief Set of functions for KTY04 manager keys management.
 */
static const mgr_key_handle_t kty04_mgr_key_handle = {
  GROUPSIG_KTY04_CODE, /**< The scheme code. */
  &kty04_mgr_key_init, /**< Initializes manager keys. */
  &kty04_mgr_key_free, /**< Frees manager keys. */
  &kty04_mgr_key_copy, /**< Copies manager keys. */
  &kty04_mgr_key_export, /**< Exports manager keys. */
  &kty04_mgr_key_import, /**< Imports manager keys. */
  &kty04_mgr_key_to_string, /**< Converts manager keys to printable strings. */
  &kty04_mgr_key_get_size_in_format,
};

#endif

/* mgr_key.h ends here */
