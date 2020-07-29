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

#ifndef _SYSENV_H
#define _SYSENV_H

/* #include <gnutls/gnutls.h> */
#include "types.h"
#include "logger.h"
#include "bigz.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__linux__) || defined(__APPLE__)
#if defined(__has_include)
#if __has_include(<sys/random.h>)
#define HAVE_GETRANDOM 1
#include <sys/random.h>
#elif __has_include(<sys/syscall.h>)
#include <sys/syscall.h>
#endif
#endif
#endif
  
/**
 * @struct sysenv_t
 * @brief System wide shared data structure.
 */
typedef struct {
  big_ctx_t big_ctx; /**< Big numbers context data structure. */
  void *data; /**< Any additional data required or that would be useful to be
		 widely accessible, but specific to individual schemes should
		 be included here. */

} sysenv_t;

/**
 * @var sysenv
 * @brief System wide shared data. Initialized by groupsig_init.
 */
sysenv_t *sysenv;

/** 
 * @fn sysenv_t* sysenv_init()
 *  @brief Initializes all system wide complex parameters (randomness, etc.)
 *
 * @param[in] seed The seed to use for PRNG. When set to UINT_MAX, a random
 *  seed will be used.
 *
 * @return A pointer to the initialized structure or NULL if error. 
 */
sysenv_t* sysenv_init(unsigned int seed);

/** 
 * @fn int sysenv_free(sysenv_t *sysenv)
 * @brief Frees all the memory allocated for sysenv.
 *
 * @param[in] sysenv Structure to free.
 * 
 * @return IOK or IERROR.
 */
int sysenv_free(sysenv_t *sysenv);

/** 
 * @fn int sysenv_getrandom(void *buf, int size)
 * @brief Uses the best available randomness source in the OS to fetch 
 *  size bytes of random data and store it in buf.
 *
 * @param[in,out] buf The buffer to store the fetched data into. Must be at least
 *  of size bytes.
 * @param[in] size The number of random bytes to fetch.
 * 
 * @return IOK or IERROR.
 */
int sysenv_getrandom(void *buf, int size);

/* /\**  */
/*  * @fn int sysenv_reseed(unsigned int seed) */
/*  * @brief Resets the seed of the PRNGs. If a seed distinct than UINT_MAX is passed,  */
/*  * that seed is used. Otherwise, a random seed is obtained. */
/*  * */
/*  * @param[in] seed The seed to use */
/*  *  */
/*  * @return IOK or IERROR. */
/*  *\/ */
/* int sysenv_reseed(unsigned int seed); */

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif

/* sysenv.h ends here */
