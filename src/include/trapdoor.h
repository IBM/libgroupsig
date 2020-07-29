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

#ifndef _TRAPDOOR_H
#define _TRAPDOOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct trapdoor_t
 * @brief Basic structure for trapdoors.
 */
typedef struct {
  uint8_t scheme; /**< The trapdoor scheme. */
  void *trap; /**< The trapdoor information. */
} trapdoor_t;

/**
 * @typedef trapdoor_t* (*trapdoor_init_f)(void);
 * @brief Type of functions for initializing trapdoors.
 *
 * @return A pointer to the initialized trapdoor or NULL if error.
 */
typedef trapdoor_t* (*trapdoor_init_f)(void);

/**
 * @typedef int (*trapdoor_free_f)(trapdoor_t *trap);
 * @brief Type of functions for freeing trapdoors.
 *
 * @param[in,out] trap The trapdoor to free.
 * 
 * @return IOK or IERROR.
 */
typedef int (*trapdoor_free_f)(trapdoor_t *trap);

/** 
 * @typedef int (*trapdoor_copy_f)(trapdoor_t *dst, trapdoor_t *src);
 * @brief Type of functions for copying trapdoors.
 *
 * @param[in,out] dst The destination trapdoor.
 * @param[in] src The source trapdoor.
 * 
 * @return IOK or IERROR.
 */
typedef int (*trapdoor_copy_f)(trapdoor_t *dst, trapdoor_t *src);

/**
 * @typedef char* (*trapdoor_to_string_f)(trapdoor_t *trap);
 * @brief Type of functions for converting trapdoors to printable strings.
 * 
 * @param[in] trap The trapdoor.
 *
 * @return A pointer to the obtained string or NULL if error.
 */
typedef char* (*trapdoor_to_string_f)(trapdoor_t *trap);

/** 
 * @typedef trapdoor_t* (*trapdoor_from_string_f)(char *strap);
 * @brief Type of functions for parsing trapdoors stored as strings.
 *
 * @param[in] strap The string to parse.
 * 
 * @return A pointer to the recovered trapdoor or NULL if error.
 */
typedef trapdoor_t* (*trapdoor_from_string_f)(char *strap);

/**
 * @struct trapdoor_handle_t
 * @brief Set of function handles for managing trapdoors.
 */
typedef struct {
  uint8_t scheme; /**< The trapdoor scheme code. */
  trapdoor_init_f init; /**< Initializes trapdoors. */
  trapdoor_free_f free; /**< Frees trapdoors. */
  trapdoor_copy_f copy; /**< Copies trapdoors. */
  trapdoor_to_string_f to_string; /**< Converts trapdoors to strings. */
  trapdoor_from_string_f from_string; /**< Parses the trapdoors stored 
					 as strings. */
} trapdoor_handle_t;

/** 
 * @fn const trapdoor_handle_t* trapdoor_handle_from_code(uint8_t code)
 * @brief Given a code, returns its associated trapdoor handle.
 * 
 * @param[in] code The code of the trapdoor handle to retrieve.
 * 
 * @return A pointer to the set of trapdoor handles or NULL if error.
 */
const trapdoor_handle_t* trapdoor_handle_from_code(uint8_t code);

/** 
 * @fn void* trapdoor_init(uint8_t code)
 * @brief Allocates memory (and sets to default values) for an ID structure of the 
 * specified group signature scheme.
 *
 * @param[in] code The code associated to the group signature scheme.
 * 
 * @return A pointer to the allocated memory.
 */
trapdoor_t* trapdoor_init(uint8_t code);

/** 
 * @fn int trapdoor_free(trapdoor_t *trap)
 * @brief Frees the memory allocated for the received ID, of the specified group
 * signature scheme.
 *
 * @param[in,out] trap The ID to free.
 * 
 * @return IOK.
 */
int trapdoor_free(trapdoor_t *trap);

/** 
 * @fn int trapdoor_copy(trapdoor_t *dst, trapdoor_t *src)
 * @brief Copies the source trapdoor into the destination trapdoor.
 *
 * @param[in,out] dst The destination trapdoor. Initialized by the caller.
 * @param[in] src The source trapdoor.
 * 
 * @return IOK or IERROR with errno set.
 */
int trapdoor_copy(trapdoor_t *dst, trapdoor_t *src);

/** 
 * @fn char* trapdoor_to_string(trapdoor_t *trap)
 * @brief Returns the string representation of the given trapdoor.
 *
 * @param[in] trap The ID to convert.
 * 
 * @return The string representation of the trapdoor.
 */
char* trapdoor_to_string(trapdoor_t *trap);

/** 
 * @fn trapdoor_t *trapdoor_from_string(uint8_t code, char *strap)
 * @brief Parses an trapdoor from a string.
 *
 * @param[in] code The code of the scheme.
 * @param[in] strap The string reprsentation of the trapdoor.
 * 
 * @return A pointer to the generated trapdoor or NULL if error.
 */
trapdoor_t *trapdoor_from_string(uint8_t code, char *strap);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _TRAPDOOR_H */

/* trapdoor.h ends here */
