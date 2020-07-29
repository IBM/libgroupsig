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

#ifndef _KTY04_TRAPDOOR_H
#define _KTY04_TRAPDOOR_H

#include "bigz.h"
#include "include/trapdoor.h"
#include "kty04.h"

/**
 * KTY04 trapdoors.
 */
typedef bigz_t kty04_trapdoor_t;

/** 
 * @fn void* kty04_trapdoor_init()
 * @brief Allocates memory for a KTY04 trapdoor and sets its values to defaults.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
trapdoor_t* kty04_trapdoor_init();

/** 
 * @fn int kty04_trapdoor_free(void *trap)
 * @brief Frees the memory allocated for a KTY04 trapdoor.
 *
 * @param[in,out] id The trapdoor to free.
 * 
 * @return IOK.
 */
int kty04_trapdoor_free(trapdoor_t *trap);

/** 
 * @fn int kty04_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src)
 * @brief Copies the source trapdoor into the destination trapdoor.
 *
 * @param[in,out] dst The destination trapdoor. Initialized by the caller.
 * @param[in] src The source trapdoor.
 * 
 * @return IOK or IERROR.
 */
int kty04_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src);

/** 
 * @fn char* kty04_trapdoor_to_string(trapdoor_t *trap)
 * @brief Converts the given KTY04 id into a printable string.
 *
 * @param[in] trap The trapdoor to convert
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* kty04_trapdoor_to_string(trapdoor_t *trap);

/** 
 * @fn trapdoor_t* kty04_trapdoor_from_string(char *strap)
 * @brief Parses the given string as  KTY04 trapdoor.
 *
 * @param[in] strap The string containing the KTY04 trapdoor.
 * 
 * @return A pointer to the retrieved KTY04 trapdoor or NULL if error.
 */
trapdoor_t* kty04_trapdoor_from_string(char *strap);

/**
 * @var kty04_trapdoor_handle
 * @brief Set of functions to manage KTY04 trapdoors.
 */
static const trapdoor_handle_t kty04_trapdoor_handle = {
  GROUPSIG_KTY04_CODE, /**< The scheme code. */
  &kty04_trapdoor_init, /**< Initializes trapdoors. */
  &kty04_trapdoor_free, /**< Frees trapdoors. */
  &kty04_trapdoor_copy, /**< Copies trapdoors. */
  &kty04_trapdoor_to_string, /**< Converts trapdoors to printable strings. */
  &kty04_trapdoor_from_string /**< Gets trapdoors from printable strings. */
};

#endif /* _KTY04_TRAPDOOR_H */

/* trapdoor.h ends here */
