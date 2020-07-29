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

#ifndef _BBS04_TRAPDOOR_H
#define _BBS04_TRAPDOOR_H

#include "include/trapdoor.h"
#include "bbs04.h"
#include "shim/pbc_ext.h"

/**
 * BBS04 trapdoors.
 */
typedef struct {
  pbcext_element_G1_t *open; /**< Open trapdoor. */
  void *trace; /**< Tracing trapdoor. BBS04 does not support tracing, hence, this
		  field will always be NULL for BBS04. */
} bbs04_trapdoor_t;

/** 
 * @fn void* bbs04_trapdoor_init()
 * @brief Allocates memory for a BBS04 trapdoor and sets its values to defaults.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
trapdoor_t* bbs04_trapdoor_init();

/** 
 * @fn int bbs04_trapdoor_free(void *trap)
 * @brief Frees the memory allocated for a BBS04 trapdoor.
 *
 * @param[in,out] id The trapdoor to free.
 * 
 * @return IOK.
 */
int bbs04_trapdoor_free(trapdoor_t *trap);

/** 
 * @fn int bbs04_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src)
 * @brief Copies the source trapdoor into the destination trapdoor.
 *
 * @param[in,out] dst The destination trapdoor. Initialized by the caller.
 * @param[in] src The source trapdoor.
 * 
 * @return IOK or IERROR.
 */
int bbs04_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src);

/** 
 * @fn char* bbs04_trapdoor_to_string(trapdoor_t *trap)
 * @brief Converts the given BBS04 id into a printable string.
 *
 * @param[in] trap The trapdoor to convert
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* bbs04_trapdoor_to_string(trapdoor_t *trap);

/** 
 * @fn trapdoor_t* bbs04_trapdoor_from_string(char *strap)
 * @brief Parses the given string as  BBS04 trapdoor.
 *
 * @param[in] strap The string containing the BBS04 trapdoor.
 * 
 * @return A pointer to the retrieved BBS04 trapdoor or NULL if error.
 */
trapdoor_t* bbs04_trapdoor_from_string(char *strap);

/**
 * @var bbs04_trapdoor_handle
 * @brief Set of functions to manage BBS04 trapdoors.
 */
static const trapdoor_handle_t bbs04_trapdoor_handle = {
  .scheme = GROUPSIG_BBS04_CODE, /**< The scheme code. */
  .init = &bbs04_trapdoor_init, /**< Initializes trapdoors. */
  .free = &bbs04_trapdoor_free, /**< Frees trapdoors. */
  .copy = &bbs04_trapdoor_copy, /**< Copies trapdoors. */
  .to_string = &bbs04_trapdoor_to_string, /**< Converts trapdoors to printable strings. */
  .from_string = &bbs04_trapdoor_from_string /**< Gets trapdoors from printable strings. */
};

/** 
 * @fn int bbs04_trapdoor_cmp(trapdoor_t *t1, trapdoor_t *t2)
 * @brief Compares the two trapdoors. Since BBS04 trapdoors only have open value,
 *  the value compared is the open field.
 *
 * @param[in] t1 The first trapdoor.
 * @param[in] t2 The second trapdoor.
 * 
 * @return 0 if both tapdoors are equal, != if not. On error, errno is updated.
 */
int bbs04_trapdoor_cmp(trapdoor_t *t1, trapdoor_t *t2);

#endif /* _BBS04_TRAPDOOR_H */

/* trapdoor.h ends here */
