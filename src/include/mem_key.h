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

#ifndef _MEM_KEY_H
#define _MEM_KEY_H

#include "key.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pointers to functions. Every type of mem_key must implement all the following 
   pointers to functions. */

/* "constructors" && "destructors" */

/**
 * @typedef groupsig_key_init_f mem_key_init_f
 * @brief Type of functions for initializing member keys.
 */
typedef groupsig_key_init_f mem_key_init_f;

/**
 * @typedef groupsig_key_free_f mem_key_free_f;
 * @brief Type of functions for freeing member keys.
 */
typedef groupsig_key_free_f mem_key_free_f;

/* Copy */

/**
 * @typedef groupsig_key_copy_f mem_key_copy_f;
 * @brief Type of functions for copying member keys.
 */
typedef groupsig_key_copy_f mem_key_copy_f;

/**
 * @typedef groupsig_key_get_size_f mem_key_get_size_f;
 * @brief Type of functions for getting the memory needed for represeting member
 *  keys in a given format.
 */
typedef groupsig_key_get_size_f mem_key_get_size_f;

/* "getters"/"setters" */
typedef groupsig_key_prv_get_f mem_key_prv_get_f;
typedef groupsig_key_pub_get_f mem_key_pub_get_f;
typedef groupsig_key_prv_set_f mem_key_prv_set_f;
typedef groupsig_key_pub_set_f mem_key_pub_set_f;

/* Export/Import */

/**
 * @typedef groupsig_key_export_f mem_key_export_f;
 * @brief Type of functions for exporting member keys.
 */
typedef groupsig_key_export_f mem_key_export_f;
typedef groupsig_key_pub_export_f mem_key_pub_export_f;
typedef groupsig_key_prv_export_f mem_key_prv_export_f;

/**
 * @typedef groupsig_key_import_f mem_key_import_f;
 * @brief Type of functions for importing member keys.
 */
typedef groupsig_key_import_f mem_key_import_f;
typedef groupsig_key_prv_import_f mem_key_prv_import_f;
typedef groupsig_key_pub_import_f mem_key_pub_import_f;

/* Conversion to human readable strings */

/**
 * @typedef groupsig_key_to_string_f mem_key_to_string_f;
 * @brief Type of functions for getting printable string representations of 
 *  member keys.
 */
typedef groupsig_key_to_string_f mem_key_to_string_f;
typedef groupsig_key_prv_to_string_f mem_key_prv_to_string_f;
typedef groupsig_key_pub_to_string_f mem_key_pub_to_string_f;

/**
 * @struct mem_key_handle_t
 * @brief Bundles together all the function handles for managing member keys.
 */
typedef struct {
  uint8_t code; /**< The scheme code. */
  mem_key_init_f init; /**< Initializes member keys. */
  mem_key_free_f free; /**< Frees member keys. */
  mem_key_copy_f copy; /**< Copies member keys. */
  mem_key_get_size_f get_size; /**< Returns the size in bytes of
				  a specific member key. */
  mem_key_export_f gexport; /**< Exports member keys.*/
  mem_key_import_f gimport; /**< Imports member keys. */
  mem_key_to_string_f to_string; /**< Returns a printable string version of 
				    member keys. */
} mem_key_handle_t;

/** 
 * @fn const mem_key_handle_t* groupsig_mem_key_handle_from_code(uint8_t code)
 * @brief Returns the bundle of function handles for the given code.
 *
 * @param[in] code The code.
 * 
 * @return A pointer to the appropriate bundle or NULL if error.
 */
const mem_key_handle_t* groupsig_mem_key_handle_from_code(uint8_t code);

/** 
 * @fn groupsig_key_t* groupsig_mem_key_init(uint8_t code)
 * @brief Initializes a member key of the given scheme.
 *
 * @param[in] code The scheme's code.
 * 
 * @return A pointer to the initialized member key or NULL if error.
 */
groupsig_key_t* groupsig_mem_key_init(uint8_t code);

/** 
 * @fn int groupsig_mem_key_free(groupsig_key_t *key)
 * @brief Frees the memory allocated for <i>key</i>.
 *
 * @param[in,out] key The key to free.
 * 
 * @return IOK or IERROR.
 */
int groupsig_mem_key_free(groupsig_key_t *key);

/** 
 * @fn int groupsig_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the member key in <i>src</i> into <i>dst</i>.
 *
 * @param[in,out] dst The destination member key. Must have been initialized by
 *  the caller.
 * @param[in] src The source member key.
 * 
 * @return IOK or IERROR.
 */
int groupsig_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int groupsig_mem_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes needed to represent <i>key</i> as an
 *  array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The number of bytes needed. On error, errno must be set appropriately.
 */
int groupsig_mem_key_get_size(groupsig_key_t *key);

/**
 * @fn int groupsig_mem_key_export(byte_t **dst, 
 *                                 uint32_t *size, 
 *                                 groupsig_key_t *key)
 * @brief Exports the given member key to the specified destination, in the 
 *  given format.
 *
 * @param[in,out] dst A pointer to the array of bytes that will contain the 
 *  exported key.
 * @param[in,out] size A pointer to a uint32_t variable that will be set to the 
 *  number of bytes written into dst.
 * @param[in] key The key to export. 
 * 
 * @return IOK or IERROR.
 */
int groupsig_mem_key_export(byte_t **dst, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* groupsig_mem_key_import(uint8_t code
 *                                             byte_t *src,
 *                                             uint32_t size)
 * @brief Imports the member key in the specified source.
 *
 * @param[in] code The scheme code.
 * @param[in] src The array of bytes to parse.
 * @param[in] size The number of bytes in <i>src</i>
 * 
 * @return A pointer to the processed member key, or NULL if error.
 */
groupsig_key_t* groupsig_mem_key_import(uint8_t code, byte_t *src, uint32_t size);

/** 
 * @fn char* groupsig_mem_key_to_string(groupsig_key_t *key);
 * @brief Returns a printable string of the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* groupsig_mem_key_to_string(groupsig_key_t *key);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _MEM_KEY_H */

/* mem_key.h ends here */
