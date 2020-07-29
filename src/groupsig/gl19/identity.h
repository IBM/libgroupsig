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

#ifndef _GL19_IDENTITY_H
#define _GL19_IDENTITY_H

#include "include/identity.h"
#include "shim/pbc_ext.h"
#include "gl19.h"

/**
 * GL19 identities.
 */
typedef pbcext_element_G1_t gl19_identity_t;

/** 
 * @fn void* gl19_identity_init()
 * @brief Allocates memory for a GL19 identity and sets its values to defaults.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
identity_t* gl19_identity_init();

/** 
 * @fn int gl19_identity_free(void *id)
 * @brief Frees the memory allocated for a GL19 identity.
 *
 * @param[in,out] id The identity to free.
 * 
 * @return IOK.
 */
int gl19_identity_free(identity_t *id);

/** 
 * @fn int gl19_identity_copy(identity_t *dst, identity_t *src)
 * @brief Copies the source identity into the destination identity.
 *
 * @param[in,out] dst The destination identity. Initialized by the caller.
 * @param[in] src The source identity.
 * 
 * @return IOK or IERROR.
 */
int gl19_identity_copy(identity_t *dst, identity_t *src);

/** 
 * @fn uint8_t gl19_identity_cmp(identity_t *id1, identity_t *id2);
 * @brief Returns 0 if both ids are the same, != 0 otherwise.
 *
 * @param[in] id1 The first id to compare. 
 * @param[in] id2 The second id to compare.
 * 
 * @return 0 if both ids are the same, != otherwise. In case of error,
 *  errno is set consequently.
 */
uint8_t gl19_identity_cmp(identity_t *id1, identity_t *id2);

/** 
 * @fn char* gl19_identity_to_string(identity_t *id)
 * @brief Converts the given GL19 id into a printable string.
 *
 * @param[in] id The ID to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* gl19_identity_to_string(identity_t *id);

/** 
 * @fn identity_t* gl19_identity_from_string(char *sid)
 * @brief Parses the given string as  GL19 identity.
 *
 * @param[in] sid The string containing the GL19 identity.
 * 
 * @return A pointer to the retrieved GL19 identity or NULL if error.
 */
identity_t* gl19_identity_from_string(char *sid);

/**
 * @var gl19_identity_handle
 * @brief Set of functions to manage GL19 identities.
 */
static const identity_handle_t gl19_identity_handle = {
  GROUPSIG_GL19_CODE, /**< Scheme code. */
  &gl19_identity_init, /**< Identity initialization. */
  &gl19_identity_free, /**< Identity free.*/
  &gl19_identity_copy, /**< Copies identities. */
  &gl19_identity_cmp, /**< Compares identities. */
  &gl19_identity_to_string, /**< Converts identities to printable strings. */
  &gl19_identity_from_string /**< Imports identities from strings. */
};

#endif /* _GL19_IDENTITY_H */

/* identity.h ends here */
