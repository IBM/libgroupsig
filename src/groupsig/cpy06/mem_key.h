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

#ifndef _CPY06_MEM_KEY_H
#define _CPY06_MEM_KEY_H

#include <stdint.h>
#include <pbc/pbc.h>
#include "types.h"
#include "sysenv.h"
#include "cpy06.h"
#include "include/mem_key.h"

/**
 * @def CPY06_MEM_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing CPY06 member keys
 */
#define CPY06_MEM_KEY_BEGIN_MSG "BEGIN CPY06 MEMBERKEY"

/**
 * @def CPY06_MEM_KEY_END_MSG
 * @brief End string to prepend to headers of files containing CPY06 member keys
 */
#define CPY06_MEM_KEY_END_MSG "END CPY06 MEMBERKEY"

/**
 * @struct cpy06_mem_key_t
 * @brief CPY06 member keys.
 */
typedef struct {
  element_t x; /**< x \in_R Z^*_p (non-adaptively chosen by member) */
  element_t t; /**< t \in_R Z^*_p (chosen by manager) */
  element_t A; /**< A = (q*g_1^x)^(1/t+\gamma) */
} cpy06_mem_key_t;

/** 
 * @fn groupsig_key_t* cpy06_mem_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* cpy06_mem_key_init();

/** 
 * @fn int cpy06_mem_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given member key.
 *
 * @param[in,out] key The member key to initialize.
 * 
 * @return IOK or IERROR
 */
int cpy06_mem_key_free(groupsig_key_t *key);

/** 
 * @fn int cpy06_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized 
 *  by the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int cpy06_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int cpy06_mem_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format)
 * @brief Returns the size that the given key would require in order to be 
 *  represented using the specified format.
 *
 * @param[in] key The key.
 * @param[in] format The format. The list of supported key formats in the CPY06
 *  scheme are defined in @ref cpy06.h.
 * 
 * @return The required number of bytes, or -1 if error.
 */
int cpy06_mem_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format);

/* int cpy06_mem_key_set_prv(groupsig_key_t *dst, groupsig_key_t *src); */
/* int cpy06_mem_key_set_pub(groupsig_key_t *dst, groupsig_key_t *src); */

/** 
 * @fn int cpy06_mem_key_export(groupsig_key_t *key, groupsig_key_format_t format,
 *                              void *dst)
 * @brief Exports the given member key, using the specified format, to the
 *  specified destination.
 *
 * @param[in] key The key to export.
 * @param[in] format The format to use. The available key formats in CPY06 are
 *  defined in @ref cpy06.h.
 * @param[in] dst The destination's information.
 * 
 * @return IOK or IERROR. 
 */
int cpy06_mem_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst);

/** 
 * @fn groupsig_key_t* cpy06_mem_key_import(groupsig_key_format_t format, void *source)
 * @brief Imports a member key from the specified source, of the specified format.
 *
 * @param[in] format The source format. The available key formats in CPY06 are
 *  defined in @ref cpy06.h.
 * @param[in] source The source information.
 * 
 * @return A pointer to the imported member key, or NULL if error.
 */
groupsig_key_t* cpy06_mem_key_import(groupsig_key_format_t format, void *source);

/** 
 * @fn char* cpy06_mem_key_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the specified member key.
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* cpy06_mem_key_to_string(groupsig_key_t *key);

/**
 * @var cpy06_mem_key_handle
 * @brief Set of functions for managing CPY06 member keys.
 */
static const mem_key_handle_t cpy06_mem_key_handle = {
  GROUPSIG_CPY06_CODE, /**< The scheme code. */
  &cpy06_mem_key_init, /**< Initializes member keys. */
  &cpy06_mem_key_free, /**< Frees member keys. */
  &cpy06_mem_key_copy, /**< Copies member keys. */
  &cpy06_mem_key_get_size_in_format, /**< Gets the size of the key in specific
					formats. */
  &cpy06_mem_key_export, /**< Exports member keys. */
  &cpy06_mem_key_import, /**< Imports member keys. */
  &cpy06_mem_key_to_string, /**< Converts member keys to printable strings. */
};

#endif /* _CPY06_MEM_KEY_H */

/* mem_key.h ends here */
