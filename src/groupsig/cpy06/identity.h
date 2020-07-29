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

#ifndef _CPY06_IDENTITY_H
#define _CPY06_IDENTITY_H

#include "include/identity.h"
#include "cpy06.h"

/**
 * CPY06 identities.
 */
typedef uint64_t cpy06_identity_t;

/** 
 * @fn void* cpy06_identity_init()
 * @brief Allocates memory for a CPY06 identity and sets its values to defaults.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
identity_t* cpy06_identity_init();

/** 
 * @fn int cpy06_identity_free(void *id)
 * @brief Frees the memory allocated for a CPY06 identity.
 *
 * @param[in,out] id The identity to free.
 * 
 * @return IOK.
 */
int cpy06_identity_free(identity_t *id);

/** 
 * @fn int cpy06_identity_copy(identity_t *dst, identity_t *src)
 * @brief Copies the source identity into the destination identity.
 *
 * @param[in,out] dst The destination identity. Initialized by the caller.
 * @param[in] src The source identity.
 * 
 * @return IOK or IERROR.
 */
int cpy06_identity_copy(identity_t *dst, identity_t *src);

/** 
 * @fn uint8_t cpy06_identity_cmp(identity_t *id1, identity_t *id2);
 * @brief Returns 0 if both ids are the same, != 0 otherwise.
 *
 * @param[in] id1 The first id to compare. 
 * @param[in] id2 The second id to compare.
 * 
 * @return 0 if both ids are the same, != otherwise. In case of error,
 *  errno is set consequently.
 */
uint8_t cpy06_identity_cmp(identity_t *id1, identity_t *id2);

/** 
 * @fn char* cpy06_identity_to_string(identity_t *id)
 * @brief Converts the given CPY06 id into a printable string.
 *
 * @param[in] id The ID to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* cpy06_identity_to_string(identity_t *id);

/** 
 * @fn identity_t* cpy06_identity_from_string(char *sid)
 * @brief Parses the given string as  CPY06 identity.
 *
 * @param[in] sid The string containing the CPY06 identity.
 * 
 * @return A pointer to the retrieved CPY06 identity or NULL if error.
 */
identity_t* cpy06_identity_from_string(char *sid);

/**
 * @var cpy06_identity_handle
 * @brief Set of functions to manage CPY06 identities.
 */
static const identity_handle_t cpy06_identity_handle = {
  GROUPSIG_CPY06_CODE, /**< Scheme code. */
  &cpy06_identity_init, /**< Identity initialization. */
  &cpy06_identity_free, /**< Identity free.*/
  &cpy06_identity_copy, /**< Copies identities. */
  &cpy06_identity_cmp, /**< Compares identities. */
  &cpy06_identity_to_string, /**< Converts identities to printable strings. */
  &cpy06_identity_from_string /**< Imports identities from strings. */
};

#endif /* _CPY06_IDENTITY_H */

/* identity.h ends here */
