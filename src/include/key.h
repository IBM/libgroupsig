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

#ifndef _GROUPSIG_KEY_H
#define _GROUPSIG_KEY_H

#include <stdint.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @typedef groupsig_key_types
 * @brief Defines all the known key types.
 */
typedef enum {
  GROUPSIG_KEY_GRPKEY, 
  GROUPSIG_KEY_MGRKEY,
  GROUPSIG_KEY_MEMKEY,
  GROUPSIG_KEY_BLDKEY,
} groupsig_key_types;

/**
 * @struct groupsig_key_t
 * @brief Basic structure for group signature schemes keys.
 */
typedef struct {
  uint8_t scheme; /**< The scheme of which this key is an instance of. */
  void *key; /**< The key itself. */
} groupsig_key_t;

/* Pointers to functions. Every type of key must implement all the following 
   pointers to functions. */

/**
 * @typedef groupsig_key_t* (*groupsig_key_init_f)(void)
 * @brief Type of functions for initializing keys.
 *
 * @return A pointer to the intialized key or NULL if error.
 */
typedef groupsig_key_t* (*groupsig_key_init_f)(void);

/** 
 * @typedef int (*groupsig_key_free_f)(groupsig_key_t *key)
 * @brief Type of functions for freeing keys.
 *
 * @param[in,out] key A pointer to the key to free.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_key_free_f)(groupsig_key_t *key);

/**
 * @typedef int (*groupsig_key_copy_f)(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Type of functions for copying keys.
 *
 * @param[in,out] dst The destiniation key. Must have been initialized by the caller.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_key_copy_f)(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @typedef int (*groupsig_key_get_size_f)(groupsig_key_t *key)
 * @brief Type of functions for determining the size of a key, once exported.
 *
 * Functions of this type return the number of bytes that a given key will need
 * to be exported.
 *
 * @param[in] key The key.
 *
 * @return The number of bytes needed to represent <i>key</i>.
 *  On error, errno must be set appropriately.
 */
typedef int (*groupsig_key_get_size_f)(groupsig_key_t *key);

/* "getters"/"setters" */
typedef groupsig_key_t* (*groupsig_key_prv_get_f)(groupsig_key_t *key);
typedef groupsig_key_t* (*groupsig_key_pub_get_f)(groupsig_key_t *key);
typedef int (*groupsig_key_prv_set_f)(void *dst, void *src);
typedef int (*groupsig_key_pub_set_f)(void *dst, void *src);

/**
 * @typedef int (*groupsig_key_export_f)(byte_t **dst, 
 *                                       uint32_t *size,
 *                                       groupsig_key_t *key)
 * @brief Type of functions for exporting keys.
 *
 * Functions of this type export <i>key</i> as an array of bytes in 
 * <i>dst</i>. If <i>*dst</i> is NULL, memory is internally allocated.
 * The number of bytes written is returned in <i>size</i>.
 * 
 * @param[in,out] dst A pointer to the array of bytes. If <i>*dst</i> is NULL,
 *  memory is internally allocated.
 * @param[in,out] size Will be set to the number of bytes written into <i>dst</i>.
 * @param[in] key The key to export.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_key_export_f)(byte_t **dst, 
				     uint32_t *size,
				     groupsig_key_t *key);
typedef int (*groupsig_key_pub_export_f)(byte_t **dst, 
					 uint32_t *size,
					 groupsig_key_t *key);
typedef int (*groupsig_key_prv_export_f)(byte_t **dst, 
					 uint32_t *size,
					 groupsig_key_t *key);

/**
 * @typedef groupsig_key_t* (*groupsig_key_import_f)(byte_t *src, uint32_t size)
 * @brief Type of functions for importing keys.
 *
 * Functions of this type import a key from the given array of bytes.
 *
 * @param[in] src The array of bytes to parse.
 * @param[in] size The number of bytes in <i>src</i>.
 *
 * @return A pointer to the recovered key or NULL if error.
 */
typedef groupsig_key_t* (*groupsig_key_import_f)(byte_t *src, uint32_t size);
typedef groupsig_key_t* (*groupsig_key_prv_import_f)(byte_t *src, uint32_t size);
typedef groupsig_key_t* (*groupsig_key_pub_import_f)(byte_t *src, uint32_t size);

/**
 * @typedef char* (*groupsig_key_to_string_f)(groupsig_key_t *key)
 * @brief Type of functions for converting keys to printable strings.
 *
 * @param[in] key The key to convert.
 *
 * @return A pointer to the produced string or NULL if error.
 */
typedef char* (*groupsig_key_to_string_f)(groupsig_key_t *key);
typedef char* (*groupsig_key_prv_to_string_f)(groupsig_key_t *key);
typedef char* (*groupsig_key_pub_to_string_f)(groupsig_key_t *key);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GROUPSIG_KEY_H */

/* key.h ends here */
