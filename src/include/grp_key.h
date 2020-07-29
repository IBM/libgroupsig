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

#ifndef _GRP_KEY_H
#define _GRP_KEY_H

#include "key.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pointers to functions. Every type of grp_key must implement all the following 
   pointers to functions. */

/* "constructors" && "destructors" */
/**
 * @typedef grp_key_init_f
 * @brief Type of functions for initializing group keys.
 */
typedef groupsig_key_init_f grp_key_init_f;

/**
 * @typedef grp_key_free_f
 * @brief Type of functions for freeing group keys.
 */
typedef groupsig_key_free_f grp_key_free_f;

/* Copy */
/**
 * @typedef grp_key_copy_f
 * @brief Type of functions for copying group keys.
 */
typedef groupsig_key_copy_f grp_key_copy_f;

/**
 * @typedef groupsig_key_get_size_f grp_key_get_size_f;
 * @brief Type of functions for getting the memory needed for representing
 * group keys.
 */
typedef groupsig_key_get_size_f grp_key_get_size_f;

/* "getters"/"setters" */
typedef groupsig_key_prv_get_f grp_key_prv_get_f;
typedef groupsig_key_pub_get_f grp_key_pub_get_f;
typedef groupsig_key_prv_set_f grp_key_prv_set_f;
typedef groupsig_key_pub_set_f grp_key_pub_set_f;

/* Export/Import */

/**
 * @typedef grp_key_export_f
 * @brief Type of functions for exporting group keys.
 */
typedef groupsig_key_export_f grp_key_export_f;
typedef groupsig_key_pub_export_f grp_key_pub_export_f;
typedef groupsig_key_prv_export_f grp_key_prv_export_f;

/**
 * @typedef grp_key_import_f
 * @brief Type of functions for importing group keys.
 */
typedef groupsig_key_import_f grp_key_import_f;
typedef groupsig_key_prv_import_f grp_key_prv_import_f;
typedef groupsig_key_pub_import_f grp_key_pub_import_f;

/* Conversion to human readable strings */

/**
 * @typedef grp_key_to_string_f
 * @brief Type of functions for converting group keys to strings.
 */
typedef groupsig_key_to_string_f grp_key_to_string_f;
typedef groupsig_key_prv_to_string_f grp_key_prv_to_string_f;
typedef groupsig_key_pub_to_string_f grp_key_pub_to_string_f;

/**
 * @struct grp_key_handle_t
 * @brief Set of functions for managing group keys.
 */
typedef struct {
  uint8_t code; /**< The group scheme. */
  grp_key_init_f init; /**< Initializes group keys. */
  grp_key_free_f free; /**< Frees group keys. */
  grp_key_copy_f copy; /**< Copies group keys. */
  grp_key_export_f gexport; /**< Exports group keys. */
  grp_key_import_f gimport; /**< Imports group keys. */
  grp_key_to_string_f to_string; /**< Gets string representations of group keys. */
  grp_key_get_size_f get_size;
} grp_key_handle_t;

/** 
 * @fn const grp_key_handle_t* groupsig_grp_key_handle_from_code(uint8_t code)
 * @brief Returns the set of handles for group keys of the specified scheme.
 *
 * @param[in] code The scheme code. 
 * 
 * @return The set of managing functions for the specified scheme or NULL
 *  if error.
 */
const grp_key_handle_t* groupsig_grp_key_handle_from_code(uint8_t code);

/** 
 * @fn groupsig_key_t* groupsig_grp_key_init(uint8_t code)
 * @brief Initializes a group key of the specified scheme.
 *
 * @param[in] code The scheme code. 
 * 
 * @return A pointer to the initialized key or NULL if error.
 */
groupsig_key_t* groupsig_grp_key_init(uint8_t code);

/** 
 * @fn int groupsig_grp_key_free(groupsig_key_t *key)
 * @brief Frees the given group key.
 *
 * @param[in,out] key The key to free. 
 * 
 * @return IOK or IERROR.
 */
int groupsig_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int groupsig_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination group key.
 *
 * @param[in,out] dst The destination group key. Must have been initialized by
 *  the caller. 
 * @param[in] src The source key. 
 * 
 * @return IOK or IERROR.
 */
int groupsig_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int groupsig_grp_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes needed to represent <i>key</i> as an
 *  array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The number of bytes needed. On error, errno must be set appropriately.
 */
int groupsig_grp_key_get_size(groupsig_key_t *key);

/**
 * @fn int groupsig_grp_key_export(byte_t **dst, 
 *                                 uint32_t *size, 
 *                                 groupsig_key_t *key)
 * @brief Exports the given group key to the specified array of bytes.
 *
 * @param[in,out] dst A pointer to the array of bytes that will contain the 
 *  exported key.
 * @param[in,out] size A pointer to a uint32_t variable that will be set to the 
 *  number of bytes written into dst.
 * @param[in] key The key to export. 
 * 
 * @return IOK or IERROR.
 */
int groupsig_grp_key_export(byte_t **dst, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* groupsig_grp_key_import(uint8_t code
 *                                             byte_t *src,
 *                                             uint32_t size)
 * @brief Imports the group key in the specified source.
 *
 * @param[in] code The scheme code.
 * @param[in] src The array of bytes to parse.
 * @param[in] size The number of bytes in <i>src</i>.
 * 
 * @return A pointer to the processed group key, or NULL if error.
 */
groupsig_key_t* groupsig_grp_key_import(uint8_t code, byte_t *src, uint32_t size);

/** 
 * @fn char* groupsig_grp_key_to_string(groupsig_key_t *key)
 * @brief Gets the string representation of the given key.
 *
 * @param[in] key The key.
 * 
 * @return A pointer to the string representation of the group key or NULL if
 *  error.
 */
char* groupsig_grp_key_to_string(groupsig_key_t *key);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GRP_KEY_H */

/* grp_key.h ends here */
