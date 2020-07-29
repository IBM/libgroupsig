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

#ifndef _IDENTITY_H
#define _IDENTITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct identity_t
 * @brief Structure for storing identities.
 */
typedef struct {
  uint8_t scheme; /**< The type of identity. */
  void *id; /**< The ID information. */
} identity_t;

/**
 * @typedef identity_t* (*identity_init_f)(void)
 * @brief Type of functions for identity initialization.
 *
 * @return A pointer to the initialized identity or NULL if error.
 */
typedef identity_t* (*identity_init_f)(void);

/**
 * @typedef int (*identity_free_f)(identity_t *id)
 * @brief Type of funtions for freeing identities.
 *
 * @param[in,out] id The identity to free.
 * 
 * @return IOK or IERROR.
 */
typedef int (*identity_free_f)(identity_t *id);

/**
 * @typedef int (*identity_copy_f)(identity_t *dst, identity_t *src)
 * @brief Function type for copying identities.
 *
 * @param[in,out] dst The (already initialized) destination identity.
 * @param[in] src The source identity.
 * 
 * @return IOK or IERROR.
 */
typedef int (*identity_copy_f)(identity_t *dst, identity_t *src);

/**
 * @typedef uint8_t (*identity_cmp_f)(identity_t *id1, identity_t *id2)
 * @brief Function type for comparing identities.
 *
 * @param[in] id1 The first identity to compare.
 * @param[in] id2 The second identity to compare.
 *
 * @return 0 if both identities are equal, != otherwise. On error, errno must
 *  be set appropriately.
 */
typedef uint8_t (*identity_cmp_f)(identity_t *id1, identity_t *id2);

/**
 * @typedef char* (*identity_to_string_f)(identity_t *id)
 * @brief Function type for converting identities to printable strings.
 *
 * @param[in] id The identity to convert.
 *
 * @return A pointer to the string representation of <i>id</i> or NULL if error.
 */
typedef char* (*identity_to_string_f)(identity_t *id);

/**
 * @typedef identity_t* (*identity_from_string_f)(char *sid);
 * @brief Function type for importing identities from printable strings.
 *
 * @param[in] sid The string representation of the identity, as produced
 *  by the corresponding function @ref identity_to_string_f.
 *
 * @return A pointer to the retrieved identity or NULL if error.
 */
typedef identity_t* (*identity_from_string_f)(char *sid);

/**
 * @struct identity_handle_t
 * @brief Struct of functions for managing identities.
 */
typedef struct {
  uint8_t scheme; /**< The ID scheme. */
  identity_init_f init; /**< Initializes identities. */
  identity_free_f free; /**< Frees identities. */
  identity_copy_f copy; /**< Copies identities. */
  identity_cmp_f cmp; /**< Compares identities. */
  identity_to_string_f to_string; /**< Converts identities to printable strings. */
  identity_from_string_f from_string; /**< Gets identities from printable strings. */
} identity_handle_t;

/** 
 * @fn const identity_handle_t* identity_handle_from_code(uint8_t code)
 * @brief Given a code, returns its associated identity handle.
 * 
 * @param[in] code The code of the identity handle to retrieve.
 * 
 * @return A pointer to the set of identity handles or NULL if error.
 */
const identity_handle_t* identity_handle_from_code(uint8_t code);

/** 
 * @fn void* identity_init(uint8_t code)
 * @brief Allocates memory (and sets to default values) for an ID structure of the 
 * specified group signature scheme.
 *
 * @param[in] code The code associated to the group signature scheme.
 * 
 * @return A pointer to the allocated memory.
 */
identity_t* identity_init(uint8_t code);

/** 
 * @fn int identity_free(identity_t *id)
 * @brief Frees the memory allocated for the received ID, of the specified group
 * signature scheme.
 *
 * @param[in,out] id The ID to free.
 * 
 * @return IOK.
 */
int identity_free(identity_t *id);

/** 
 * @fn int identity_copy(identity_t *dst, identity_t *src)
 * @brief Copies the source identity into the destination identity.
 *
 * @param[in,out] dst The destination identity. Initialized by the caller.
 * @param[in] src The source identity.
 * 
 * @return IOK or IERROR with errno set.
 */
int identity_copy(identity_t *dst, identity_t *src);

/** 
 * @fn uint8_t identity_cmp(identity_t *id1, identity_t *id2);
 * @brief Returns 0 if both identities are the same, != otherwise.
 *
 * @param[in] id1 The first identity.
 * @param[in] id2 The second identity.
 * 
 * @return 0 if both identities are the same, != 0 otherwise. errno is set
 *  in case of error.
 */
uint8_t identity_cmp(identity_t *id1, identity_t *id2);

/** 
 * @fn char* identity_to_string(identity_t *id)
 * @brief Returns the string representation of the given identity.
 *
 * @param[in] id The ID to convert.
 * 
 * @return The string representation of the identity.
 */
char* identity_to_string(identity_t *id);

/** 
 * @fn identity_t *identity_from_string(uint8_t code, char *sid)
 * @brief Parses an identity from a string.
 *
 * @param[in] code The code of the scheme.
 * @param[in] sid The string reprsentation of the identity.
 * 
 * @return A pointer to the generated identity or NULL if error.
 */
identity_t *identity_from_string(uint8_t code, char *sid);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _IDENTITY_H */

/* identity.h ends here */
