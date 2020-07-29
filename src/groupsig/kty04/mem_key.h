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

#ifndef _KTY04_MEM_KEY_H
#define _KTY04_MEM_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "groupsig/kty04/sphere.h"
#include "kty04.h"
#include "include/mem_key.h"

/**
 * @def KTY04_MEM_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing KTY04 member keys
 */
#define KTY04_MEM_KEY_BEGIN_MSG "BEGIN KTY04 MEMBERKEY"

/**
 * @def KTY04_MEM_KEY_END_MSG
 * @brief End string to prepend to headers of files containing KTY04 member keys
 */
#define KTY04_MEM_KEY_END_MSG "END KTY04 MEMBERKEY"

/**
 * @struct kty04_mem_key_t
 * @brief Defines the member keys of the KTY04 scheme.
 */
typedef struct {
  bigz_t A; /**< A = (C*a^x*a0)^(e^(-1)) (mod n) */
  bigz_t C; /**< C = b^x (mod n) */
  bigz_t x; /**< An element chosen at random from the inner sphere of lambda */
  bigz_t xx; /**< The random power */
  bigz_t e; /**< The e used to obtain A */
} kty04_mem_key_t;

/** 
 * @fn groupsig_key_t* kty04_mem_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* kty04_mem_key_init();

/** 
 * @fn int kty04_mem_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given member key.
 *
 * @param[in,out] key The member key to initialize.
 * 
 * @return IOK or IERROR
 */
int kty04_mem_key_free(groupsig_key_t *key);

/** 
 * @fn int kty04_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized 
 *  by the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int kty04_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int kty04_mem_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format)
 * @brief Returns the size that the given key would require in order to be 
 *  represented using the specified format.
 *
 * @param[in] key The key.
 * @param[in] format The format. The list of supported key formats in the KTY04
 *  scheme are defined in @ref kty04.h.
 * 
 * @return The required number of bytes, or -1 if error.
 */
int kty04_mem_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format);

/** 
 * @fn groupsig_key_t* kty04_mem_key_get_prv(groupsig_key_t *key)
 * @brief Gets a partial member key with only the private part of the
 *  received key.
 *
 * In a member key, private part refers to the parts that are not known to any
 * other entity, including the Group Manager. In this case, this corresponds
 * to the x' (xx in the code) field.
 *
 * @param[in] key The member key.
 * 
 * @return An internally allocated member key with the private part of <i>key</i>
 *  set, and the rest of the fields set to NULL. On error, NULL is returned.
 */
groupsig_key_t* kty04_mem_key_get_prv(groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* kty04_mem_key_get_pub(groupsig_key_t *key)
 * @brief Returns a new member key in which only the public part of the
 *  received key is set.
 *
 * With "public" part of a member key, we refer to the parts that are known to
 * the Group Manager. However, these parts are not known to any other entity.
 * For KTY04 member keys, this corresponds to all fields but x' (xx in the code).
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the produced "public" member key, or NULL if error.
 */
groupsig_key_t* kty04_mem_key_get_pub(groupsig_key_t *key);

/* int kty04_mem_key_set_prv(groupsig_key_t *dst, groupsig_key_t *src); */
/* int kty04_mem_key_set_pub(groupsig_key_t *dst, groupsig_key_t *src); */

/** 
 * @fn int kty04_mem_key_export(groupsig_key_t *key, groupsig_key_format_t format,
 *                              void *dst)
 * @brief Exports the given member key, using the specified format, to the
 *  specified destination.
 *
 * @param[in] key The key to export.
 * @param[in] format The format to use. The available key formats in KTY04 are
 *  defined in @ref kty04.h.
 * @param[in] dst The destination's information.
 * 
 * @return IOK or IERROR. 
 */
int kty04_mem_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst);

/** 
 * @fn int kty04_mem_key_export_pub(groupsig_key_t *key, 
 *                                  groupsig_key_format_t format, void *dst)
 * @brief Exports the "public" part of the given member key.
 *
 * @param[in] key The key to export.
 * @param[in] format The format to use. The available key formats in KTY04 are
 *  defined in @ref kty04.h.
 * @param[in] dst The destination information.
 * 
 * @return IOK or IERROR.
 */
int kty04_mem_key_export_pub(groupsig_key_t *key, groupsig_key_format_t format, void *dst);

/** 
 * @fn int kty04_mem_key_export_prv(groupsig_key_t *key, 
 *                                  groupsig_key_format_t format, void *dst)
 * @brief Exports the "private" part of the given member key.
 *
 * @param[in] key The key to export.
 * @param[in] format The format to use. The available key formats in KTY04 are
 *  defined in @ref kty04.h.
 * @param[in] dst The destination.
 * 
 * @return 
 */
int kty04_mem_key_export_prv(groupsig_key_t *key, groupsig_key_format_t format, void *dst);

/** 
 * @fn groupsig_key_t* kty04_mem_key_import(groupsig_key_format_t format, void *source)
 * @brief Imports a member key from the specified source, of the specified format.
 *
 * @param[in] format The source format. The available key formats in KTY04 are
 *  defined in @ref kty04.h.
 * @param[in] source The source information.
 * 
 * @return A pointer to the imported member key, or NULL if error.
 */
groupsig_key_t* kty04_mem_key_import(groupsig_key_format_t format, void *source);
groupsig_key_t* kty04_mem_key_import_prv(groupsig_key_format_t format, void *source);
groupsig_key_t* kty04_mem_key_import_pub(groupsig_key_format_t format, void *source);

/** 
 * @fn char* kty04_mem_key_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the specified member key.
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* kty04_mem_key_to_string(groupsig_key_t *key);

/** 
 * @fn char* kty04_mem_key_prv_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the "private" part of the
 *  specified member key.
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* kty04_mem_key_prv_to_string(groupsig_key_t *key);

/** 
 * @fn char* kty04_mem_key_pub_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the "public" part of the
 *  specified member key.
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* kty04_mem_key_pub_to_string(groupsig_key_t *key);

/**
 * @var kty04_mem_key_handle
 * @brief Set of functions for managing KTY04 member keys.
 */
static const mem_key_handle_t kty04_mem_key_handle = {
  GROUPSIG_KTY04_CODE, /**< The scheme code. */
  &kty04_mem_key_init, /**< Initializes member keys. */
  &kty04_mem_key_free, /**< Frees member keys. */
  &kty04_mem_key_copy, /**< Copies member keys. */
  &kty04_mem_key_get_size_in_format, /**< Gets the size of the key in specific
					formats. */
  &kty04_mem_key_export, /**< Exports member keys. */
  &kty04_mem_key_import, /**< Imports member keys. */
  &kty04_mem_key_to_string, /**< Converts member keys to printable strings. */
};

#endif /* _KTY04_MEM_KEY_H */

/* mem_key.h ends here */
