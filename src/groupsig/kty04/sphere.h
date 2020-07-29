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

#ifndef _SPHERE_H
#define _SPHERE_H

#include <stdio.h>
#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "bigz.h"

/**
 * @struct sphere_t
 * @brief Type definition for the spheres used in KTY04
 */
typedef struct {
  bigz_t center; /**< The center of the sphere. */
  bigz_t radius; /**< The radius of the sphere. */
} sphere_t;

/** 
 * @fn sphere_t* sphere_init()
 * @brief Creates a sphere "object". Initializing all its internal fields.
 *
 * @return The created object or NULL if error.
 */
sphere_t* sphere_init();

/** 
 * @fn int sphere_free(sphere_t *sp)
 * @brief Frees the memory of a sphere allocated using sphere_init.
 *
 * @param[in,out] sp The sphere to free.
 * 
 * @return IOK or IERROR
 */
int sphere_free(sphere_t *sp);

/** 
 * @fn int sphere_get_min(sphere_t *sp, bigz_t min)
 * @brief Gets the minimum possible value of the given sphere.
 *
 * @param[in] sp The sphere.
 * @param[in,out] min Will be set to the minimum value of the sphere.
 * 
 * @return IOK or IERROR
 */
int sphere_get_min(sphere_t *sp, bigz_t min);

/** 
 * @fn int sphere_get_max(sphere_t *sp, bigz_t max)
 * @brief Gets the maximum possible value of the given sphere.
 *
 * @param[in] sp The sphere.
 * @param[in,out] max Will be set to the maximum value of the sphere.
 * 
 * @return IOK or IERROR
 */
int sphere_get_max(sphere_t *sp, bigz_t max);

/** 
 * @fn int sphere_get_inner(sphere_t *sp, uint64_t epsilon, uint64_t k, 
 *                                 sphere_t *inner)
 * @brief Gets the inner sphere associated to <i>sp</i>, according to the 
 *  definition given in KTY04.
 *
 * @param[in] sp The "original" sphere.
 * @param[in] epsilon The epsilon parameter required by KTY04.
 * @param[in] k The k parameter required by KTY04.
 * @param[in,out] inner An initialized sphere that will be set to the inner
 *  sphere associated to <i>sp</i>.
 * 
 * @return IOK or IERROR
 */
int sphere_get_inner(sphere_t *sp, uint64_t epsilon, uint64_t k, 
			    sphere_t *inner);

/** 
 * @fn int sphere_get_random(sphere_t *sp, bigz_t r)
 * @brief Returns a random element in the sphere <i>sp</i>.
 *
 * @param[in] sp The sphere.
 * @param[in,out] r Will be set to the random element.
 * 
 * @return IOK or IERROR
 */
int sphere_get_random(sphere_t *sp, bigz_t r);

/** 
 * @fn int sphere_get_random_prime(sphere_t *sp, bigz_t p)
 * @brief Gets a random prime in the sphere. 
 *
 * @param[in] sp The sphere.
 * @param[in,out] p Will be set to the chosen random prime.
 * 
 * @return IOK or IERROR
 */
int sphere_get_random_prime(sphere_t *sp, bigz_t p);

/** 
 * @fn int sphere_get_product_spheres(sphere_t *sp1, 
 *                                          sphere_t *sp2, 
 *				            sphere_t *sp)
 * @brief Calculates the product of two spheres.
 *
 * The interval defined by the product of two intervals (spheres), assuming
 * both intervals range in >= 0, is: [min1*min2,max1*max2], where min|max1, 
 * min|max2 are the min|max value of sphere 1 and the min|max value of sphere 2.
 * 
 * @param[in] sp1 The 'first' sphere.
 * @param[in] sp2 The 'second' sphere.
 * @param[in,out] sp The result of sp1*sp2.
 * 
 * @return IOK or IERROR
 */
int sphere_get_product_spheres(sphere_t *sp1, sphere_t *sp2, 
				     sphere_t *sp);

/** 
 * @fn char* sphere_to_string(sphere_t *sp)
 * @brief Returns a readable string representation of the given sphere
 * 
 * @param[in] sp The sphere to print.
 * 
 * @return The created string or NULL if error
 */
char* sphere_to_string(sphere_t *sp);

#endif 

/* sphere.h ends here */
