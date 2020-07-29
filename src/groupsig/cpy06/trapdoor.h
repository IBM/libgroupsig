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

#ifndef _CPY06_TRAPDOOR_H
#define _CPY06_TRAPDOOR_H

#include <pbc/pbc.h>
#include "bigz.h"
#include "include/trapdoor.h"
#include "cpy06.h"

/**
 * CPY06 trapdoors.
 */
typedef struct {
  element_t open; /**< Open trapdoor. In CPY06, the A value computed during join. */
  element_t trace; /**< Tracing trapdoor. In CPY06, the C value computed during join. */
} cpy06_trapdoor_t;

/** 
 * @fn void* cpy06_trapdoor_init()
 * @brief Allocates memory for a CPY06 trapdoor and sets its values to defaults.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
trapdoor_t* cpy06_trapdoor_init();

/** 
 * @fn int cpy06_trapdoor_free(void *trap)
 * @brief Frees the memory allocated for a CPY06 trapdoor.
 *
 * @param[in,out] id The trapdoor to free.
 * 
 * @return IOK.
 */
int cpy06_trapdoor_free(trapdoor_t *trap);

/** 
 * @fn int cpy06_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src)
 * @brief Copies the source trapdoor into the destination trapdoor.
 *
 * @param[in,out] dst The destination trapdoor. Initialized by the caller.
 * @param[in] src The source trapdoor.
 * 
 * @return IOK or IERROR.
 */
int cpy06_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src);

/** 
 * @fn char* cpy06_trapdoor_to_string(trapdoor_t *trap)
 * @brief Converts the given CPY06 id into a printable string.
 *
 * @param[in] trap The trapdoor to convert
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* cpy06_trapdoor_to_string(trapdoor_t *trap);

/** 
 * @fn trapdoor_t* cpy06_trapdoor_from_string(char *strap)
 * @brief Parses the given string as  CPY06 trapdoor.
 *
 * @param[in] strap The string containing the CPY06 trapdoor.
 * 
 * @return A pointer to the retrieved CPY06 trapdoor or NULL if error.
 */
trapdoor_t* cpy06_trapdoor_from_string(char *strap);

/**
 * @var cpy06_trapdoor_handle
 * @brief Set of functions to manage CPY06 trapdoors.
 */
static const trapdoor_handle_t cpy06_trapdoor_handle = {
  GROUPSIG_CPY06_CODE, /**< The scheme code. */
  &cpy06_trapdoor_init, /**< Initializes trapdoors. */
  &cpy06_trapdoor_free, /**< Frees trapdoors. */
  &cpy06_trapdoor_copy, /**< Copies trapdoors. */
  &cpy06_trapdoor_to_string, /**< Converts trapdoors to printable strings. */
  &cpy06_trapdoor_from_string /**< Gets trapdoors from printable strings. */
};

/** 
 * @fn int cpy06_trapdoor_cmp(trapdoor_t *t1, trapdoor_t *t2)
 * @brief Compares the two trapdoors. Since CPY06 trapdoors only have open value,
 *  the value compared is the open field.
 *
 * @param[in] t1 The first trapdoor.
 * @param[in] t2 The second trapdoor.
 * 
 * @return 0 if both tapdoors are equal, != if not. On error, errno is updated.
 */
int cpy06_trapdoor_cmp(trapdoor_t *t1, trapdoor_t *t2);

#endif /* _CPY06_TRAPDOOR_H */

/* trapdoor.h ends here */
