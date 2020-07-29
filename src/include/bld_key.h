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

#ifndef _BLD_KEY_H
#define _BLD_KEY_H

#include "key.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pointers to functions. Every type of bld_key must implement all the following 
   pointers to functions. */

/* "constructors" && "destructors" */

/**
 * @typedef groupsig_key_init_f bld_key_init_f
 * @brief Type of functions for initializing blinding keys.
 */
typedef groupsig_key_init_f bld_key_init_f;

/**
 * @typedef groupsig_key_free_f bld_key_free_f;
 * @brief Type of functions for freeing blinding keys.
 */
typedef groupsig_key_free_f bld_key_free_f;

/**
 * @typedef groupsig_key_free_f bld_key_random_f;
 * @brief Type of functions for randomly setting blinding keys.
 */
typedef groupsig_key_t* (*bld_key_random_f)(void *param);

/* Copy */

/**
 * @typedef groupsig_key_copy_f bld_key_copy_f;
 * @brief Type of functions for copying blinding keys.
 */
typedef groupsig_key_copy_f bld_key_copy_f;

/**
 * @typedef groupsig_key_get_size_f bld_key_get_size_f;
 * @brief Type of functions for getting the memory needed for represeting blinding
 *  keys in a given format.
 */
typedef groupsig_key_get_size_f bld_key_get_size_f;

/* "getters"/"setters" */
typedef groupsig_key_prv_get_f bld_key_prv_get_f;
typedef groupsig_key_pub_get_f bld_key_pub_get_f;
typedef groupsig_key_prv_set_f bld_key_prv_set_f;
typedef groupsig_key_pub_set_f bld_key_pub_set_f;

/* Export/Import */

/**
 * @typedef groupsig_key_export_f bld_key_export_f;
 * @brief Type of functions for exporting blinding keys.
 */
typedef groupsig_key_export_f bld_key_export_f;
typedef groupsig_key_pub_export_f bld_key_pub_export_f;
typedef groupsig_key_prv_export_f bld_key_prv_export_f;

/**
 * @typedef groupsig_key_import_f bld_key_import_f;
 * @brief Type of functions for importing blinding keys.
 */
typedef groupsig_key_import_f bld_key_import_f;
typedef groupsig_key_prv_import_f bld_key_prv_import_f;
typedef groupsig_key_pub_import_f bld_key_pub_import_f;

/* Conversion to human readable strings */

/**
 * @typedef groupsig_key_to_string_f bld_key_to_string_f;
 * @brief Type of functions for getting printable string representations of 
 *  blinding keys.
 */
typedef groupsig_key_to_string_f bld_key_to_string_f;
typedef groupsig_key_prv_to_string_f bld_key_prv_to_string_f;
typedef groupsig_key_pub_to_string_f bld_key_pub_to_string_f;

/**
 * @struct bld_key_handle_t
 * @brief Bundles together all the function handles for managing blinding keys.
 */
typedef struct {
  uint8_t code; /**< The scheme code. */
  bld_key_init_f init; /**< Initializes blinding keys. */
  bld_key_free_f free; /**< Frees blinding keys. */
  bld_key_random_f random; /**< Randomly sets blinding keys. */
  bld_key_copy_f copy; /**< Copies blinding keys. */
  bld_key_export_f gexport; /**< Exports a full blinding key.*/
  bld_key_pub_export_f gexport_pub; /**< Exports the public key of a blinding key. */
  bld_key_prv_export_f gexport_prv; /**< Exports the private key of a blinding key. */
  bld_key_import_f gimport; /**< Imports a blinding key (public, private, or full). */
  bld_key_to_string_f to_string; /**< Returns a printable string version of 
				    blinding keys. */
  bld_key_get_size_f get_size; /**< Returns the size in bytes of
				  a specific blinding key. */
} bld_key_handle_t;

/** 
 * @fn const bld_key_handle_t* groupsig_bld_key_handle_from_code(uint8_t code)
 * @brief Returns the bundle of function handles for the given code.
 *
 * @param[in] code The code.
 * 
 * @return A pointer to the appropriate bundle or NULL if error.
 */
const bld_key_handle_t* groupsig_bld_key_handle_from_code(uint8_t code);

/** 
 * @fn groupsig_key_t* groupsig_bld_key_init(uint8_t code)
 * @brief Initializes a blinding key of the given scheme.
 *
 * @param[in] code The scheme's code.
 * 
 * @return A pointer to the initialized blinding key or NULL if error.
 */
groupsig_key_t* groupsig_bld_key_init(uint8_t code);

/** 
 * @fn int groupsig_bld_key_free(groupsig_key_t *key)
 * @brief Frees the memory allocated for <i>key</i>.
 *
 * @param[in,out] key The key to free.
 * 
 * @return IOK or IERROR.
 */
int groupsig_bld_key_free(groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* groupsig_bld_key_random(uint8_t code, void *param)
 * @brief Sets <i>key</i> to an appropriate random value.
 *
 * @param[in] The code of the scheme.
 * @param[in] param Additional values needed to setup.
 * 
 * @return The randomly initialized blinding key, or NULL if error.
 */
groupsig_key_t* groupsig_bld_key_random(uint8_t code, void *param);

/** 
 * @fn int groupsig_bld_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the blinding key in <i>src</i> into <i>dst</i>.
 *
 * @param[in,out] dst The destination blinding key. Must have been initialized by
 *  the caller.
 * @param[in] src The source blinding key.
 * 
 * @return IOK or IERROR.
 */
int groupsig_bld_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int groupsig_bld_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes needed to represent <i>key</i> as an
 *  array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The number of bytes needed. On error, errno must be set appropriately.
 */
int groupsig_bld_key_get_size(groupsig_key_t *key);

/**
 * @fn int groupsig_bld_key_export(byte_t **dst, 
 *                                 uint32_t *size, 
 *                                 groupsig_key_t *key)
 * @brief Exports the given blinding key to the specified destination, in the 
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
int groupsig_bld_key_export(byte_t **dst, uint32_t *size, groupsig_key_t *key);
   
/** 
 * @fn int groupsig_bld_key_export_pub(byte_t **dst, uint32_t *size, 
 *                                     groupsig_key_t *key);
 * @brief Exports the blinding key in <i>key</i> to <i>dst</i> using the format
 *  <i>format</i>.
 *
 * @param[in,out] dst A pointer to the array of bytes that will contain the 
 *  exported key.
 * @param[in,out] size A pointer to a uint32_t variable that will be set to the 
 *  number of bytes written into dst.
 * @param[in] key The key to export. 
 * 
 * @return IOK or IERROR.
 */
int groupsig_bld_key_export_pub(byte_t **dst, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn int groupsig_bld_key_export_pub(byte_t **dst, uint32_t *size, 
 *                                     groupsig_key_t *key);
 * @brief Exports the blinding key in <i>key</i> to <i>dst</i> using the format
 *  <i>format</i>.
 *
 * @param[in,out] dst A pointer to the array of bytes that will contain the 
 *  exported key.
 * @param[in,out] size A pointer to a uint32_t variable that will be set to the 
 *  number of bytes written into dst.
 * @param[in] key The key to export. 
 * 
 * @return IOK or IERROR.
 */
int groupsig_bld_key_export_prv(byte_t **dst, uint32_t *size, groupsig_key_t *key);
  
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
groupsig_key_t* groupsig_bld_key_import(uint8_t code, byte_t *src, uint32_t size);

/** 
 * @fn char* groupsig_bld_key_to_string(groupsig_key_t *key);
 * @brief Returns a printable string of the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* groupsig_bld_key_to_string(groupsig_key_t *key);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _BLD_KEY_H */

/* bld_key.h ends here */
