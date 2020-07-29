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

#ifndef _KTY04_GRP_KEY_H
#define _KTY04_GRP_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "groupsig/kty04/sphere.h"
#include "kty04.h"
#include "include/grp_key.h"

/**
 * @struct kty04_grp_key_t
 * @brief Structure for KTY04 group keys.
 *
 * Defines the "group" keys of the KTY04 scheme. The p and q components of the 
 * associated manager key must satisfy n = p*q. The spheres are not really
 * necessary, since we have nu and epsilon, but it will reduce the amount of
 * computations required for the procedures.
 */
typedef struct {
  bigz_t n; /**< The group modulus */
  bigz_t a; /**< */
  bigz_t a0; /**< */
  bigz_t b; /**< */
  bigz_t g; /**< */
  bigz_t h; /**< */
  bigz_t y; /**< */
  uint64_t epsilon; /**< Controls the statistical indistinguishability. */
  uint64_t nu; /**< The parameter defining the spheres. */
  uint64_t k; /**< The security parameter. */
  sphere_t *lambda; /* The lambda sphere. */
  sphere_t *inner_lambda; /* The inner lambda sphere. */
  sphere_t *M; /* The M sphere. */
  sphere_t *inner_M; /* The inner M sphere. */
  sphere_t *gamma; /* The gamma sphere. */
  sphere_t *inner_gamma; /* The inner gamma sphere. */
} kty04_grp_key_t;

/**
 * @def KTY04_GRP_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing KTY04 group keys
 */
#define KTY04_GRP_KEY_BEGIN_MSG "BEGIN KTY04 GROUPKEY"

/**
 * @def KTY04_GRP_KEY_END_MSG
 * @brief End string to prepend to headers of files containing KTY04 group keys
 */
#define KTY04_GRP_KEY_END_MSG "END KTY04 GROUPKEY"

/** 
 * @fn groupsig_key_t* kty04_grp_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* kty04_grp_key_init();

/** 
 * @fn int kty04_grp_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given group key.
 *
 * @param[in,out] key The group key to initialize.
 * 
 * @return IOK or IERROR
 */
int kty04_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int kty04_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies a group key.
 *
 * Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int kty04_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @fn int kty04_grp_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format)
 * @brief Returns the size that the given key would require in order to be
 *  represented using the specified format.
 *
 * @param[in] key The key.
 * @param[in] format The format. The list of supported key formats in the KTY04
 *  scheme are defined in @ref kty04.h.
 *
 * @return The required number of bytes, or -1 if error.
 */
int kty04_grp_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format);

/** 
 * @fn int kty04_grp_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst)
 * @brief Exports the given group key.
 *
 * Exports the given KTY04 group key, to the specified destination, using the given format.
 *
 * @param[in] key The group key to export.
 * @param[in] format The format to use for exporting the key. The available key 
 *  formats in KTY04 are defined in @ref kty04.h.
 * @param[in] dst The destination's description.
 * 
 * @return IOK or IERROR.
 */
int kty04_grp_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst);

/** 
 * @fn groupsig_key_t* kty04_grp_key_import(groupsig_key_format_t format, void *source)
 * @brief Imports a group key.
 *
 * Imports a KTY04 group key from the specified source, of the specified format.
 * 
 * @param[in] format The source format. The available key formats in KTY04 are
 *  defined in @ref kty04.h.
 * @param[in] source The source's description.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* kty04_grp_key_import(groupsig_key_format_t format, void *source);

/** 
 * @fn char* kty04_grp_key_to_string(groupsig_key_t *key)
 * @brief Converts the key to a printable string.
 *
 * Returns a printable string associated to the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return The printable string associated to the key, or NULL if error.
 */
char* kty04_grp_key_to_string(groupsig_key_t *key);

/** 
 * @fn int kty04_grp_key_set_spheres_std(kty04_grp_key_t *key)
 * @brief Sets the given key's spheres to the default configuration.
 *
 * Sets the given key's spheres to the configuration specified in the
 * KTY04 paper "Traceable Signatures".
 *
 * @param[in,out] key An initialized key, with all the fields set but the
 *  spheres.
 * 
 * @return IOK or IERROR.
 */
int kty04_grp_key_set_spheres_std(kty04_grp_key_t *key);

/**
 * @var kty04_grp_key_handle
 * @brief The set of functions to manage KTY04 group keys.
 */
static const grp_key_handle_t kty04_grp_key_handle = {
  GROUPSIG_KTY04_CODE, /**< Scheme. */
  &kty04_grp_key_init, /**< Initialize group keys. */
  &kty04_grp_key_free, /**< Free group keys. */
  &kty04_grp_key_copy, /**< Copy group keys. */
  &kty04_grp_key_export, /**< Export group keys. */
  &kty04_grp_key_import, /**< Import group keys. */
  &kty04_grp_key_to_string, /**< Convert to printable strings. */
  &kty04_grp_key_get_size_in_format,
};

#endif

/* grp_key.h ends here */
