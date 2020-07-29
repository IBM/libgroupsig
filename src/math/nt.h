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

#ifndef _NT_H
#define _NT_H

#include <stdint.h>

#include "types.h"
#include "sysenv.h"
#include "bigz.h"
//#include "bigf.h"

#define PRECISION 1000000.f /** Used to generate random floating point nt */

/**
 * @def SQRT2 
 * @brief The square root of 2 (until its 76-th decimal digit).
 * See http://apod.nasa.gov/htmltest/gifcity/sqrt2.1mil
 */
#define SQRT2 1.4142135623730950488016887242096980785696718753769480731766797379907324784621

/**
 * @def PRIMALITY_TEST_SEC
 * @brief Sets the level of security to use in primality tests (for now, just the 
 *  GMP primality test)
 */
#define PRIMALITY_TEST_SEC 10 

/**
 * @def NT_LOG_PRECISSION 
 * @brief Number of decimals to calculate for logarithms
 */
#define NT_LOG_PRECISSION 1000

/**
 * @struct factor_list_t
 * @brief Structure for storing a list of factors of a given number.
 * Note that the list won't necessarily be ordered.
 */
typedef struct {
  uint32_t n; /**< Number of elements in factors. */
  bigz_t *factors; /**< List of factors. */
  bigz_t max_factor; /**< The maximum factor in factors. */
  bigz_t min_factor; /**< The minimum factor in factors. */
} factor_list_t;

/** 
 * @fn int nt_factor_list_init(factor_list_t *factors)
 * @brief Initializes the internal fields of factors of a given number.
 * 
 * @param[in,out] factors The factors list structure to initialize.
 * 
 * @return IOK or IERROR
 */
int nt_factor_list_init(factor_list_t *factors);

/** 
 * @fn int nt_factor_list_free(factor_list_t *factors)
 * @brief Frees the memory allocated for the internal elements of factors.
 * 
 * @param[in,out] factors The factors list structure to free.
 * 
 * @return IOK or IERROR
 */
int nt_factor_list_free(factor_list_t *factors);

/** 
 * @fn int nt_factor_list_insert(factor_list_t *factors, bigz_t *factor)
 * @brief Inserts the new factor at the end of the given factors list.
 * 
 * @param[in,out] factors The factors list.
 * @param[in] factor The factor to insert.
 * 
 * @return IOK or IERROR
 */
int nt_factor_list_insert(factor_list_t *factors, bigz_t factor);

/** 
 * @fn int nt_factor_list_insert_ui(factor_list_t *factors, uint64_t factor)
 * @brief The same as nt_factor_list_insert, but for uint64_t factors.
 * 
 * @param[in,out] factors The factor list to be updated.
 * @param[in] factor The factor.
 * 
 * @return IOK or IERROR
 */
int nt_factor_list_insert_ui(factor_list_t *factors, uint64_t factor);

/** 
 * @fn int nt_factor_list_fprintf(FILE *fd, factor_list_t *factors)
 * @brief Prints the information in the given factors lists.
 *
 * @param[in] fd File descriptor to print into.
 * @param[in] factors The factors lists
 * 
 * @return IOK or IERROR
 */
int nt_factor_list_fprintf(FILE *fd, factor_list_t *factors);

/** 
 * @fn int nt_is_factor_list_complete(bigz_t n, factor_list_t *factors, 
 *                                         uint8_t *b)
 * @brief Checks whether the given factor list is a complete factorization of
 *  n.
 *
 * @param[in] n The integer.
 * @param[in] factors A list of facdtors of n.
 * @param[in,out] b Will be set to 1 if the factor list is complete, to 0 
 *  otherwise.
 * 
 * @return IOK or IERROR
 */
int nt_is_factor_list_complete(bigz_t n, factor_list_t *factors, uint8_t *b);

/** 
 * @fn int nt_trial_division_65536(bigz_t z, factor_list_t *factors)
 * @brief Divides z by the primes up to 65536, and stores any found factor in
 *  the given factors list.
 *
 * @param[in] z The integer to test.
 * @param[in,out] factors The factors list.
 * 
 * @return IOK or IERROR
 */
int nt_trial_division_65536(bigz_t z, factor_list_t *factors);

/** 
 * @fn int nt_genprime_random(uint64_t primesize, bigz_t *p)
 * @brief Generates a random prime of no less than, and approximately of, 
 *  primesize bits.
 *
 * PREREQUISITE: srand() must have been initialized.
 *
 * @param[in] primesize The number of bits of the prime to generate.
 * @param[in,out] p The bigz_t to store the generated prime.
 * 
 * @return IOK or IERROR
 */
int nt_genprime_random(uint64_t primesize, bigz_t *p);

/** 
 * @fn int nt_genprime_random_interval(bigz_t low, bigz_t up, bigz_t p)
 * @brief Generates a random prime in the interval [low,up].
 *
 * @param[in] low The lower limit of the interval. 
 * @param[in] up The upper limit of the interval.
 * @param[in,out] p Will be set to the generated prime.
 * 
 * @return IOK
 */
int nt_genprime_random_interval(bigz_t low, bigz_t up, bigz_t p);

/** 
 * @fn int nt_mov97_alg462(uint64_t k, bigz_t *p, factor_list_t *factors)
 * @brief Implements the algorithm 4.62 of Menezes et al., for generating provable
 * primes of the form p = 2Rq+1, with q prime, using Maurer's algorithm. 
 * 
 * @param[in] k The length, in bits, of the desired prime.
 * @param[in,out] p Will store the generated proven prime.
 * @param[in,out] factors Will store a list of factors of p-1.
 *  @todo The returned list is not a complete list of all p-1 factors.
 * 
 * @return IOK or IERROR
 */
int nt_mov97_alg462(uint64_t k, bigz_t *p, factor_list_t *factors);

/** 
 * @fn int nt_mov97_alg462_mod(bigz_t p1, bigz_t p2, bigz_t p, factor_list_t *factors)
 * @brief Generates a proven prime using a modified version of algorithm 4.62 of
 *  Menezes et al. "Handbook of applied cryptography". The generated prime is of
 *  the form p = 2*r*p1*p2*q+1, where r is a random integer and q is a prime.
 * 
 * @param[in] p1 First prime divisor of p-1.
 * @param[in] p2 Second prime divisor of p-1.
 * @param[in,out] p The generated prime.
 * @param[in,out] factors When not null, will store a list of factors of p-1. 
 *
 *  @todo The returned list may not be a complete list of all p-1 factors (and it won't
 *   if the generated R has a prime factor bigger than 2^16).
 * 
 * @return IOK or IERROR
 */
int nt_mov97_alg462_mod(bigz_t p1, bigz_t p2, bigz_t *p, factor_list_t *factors);

/** 
 * @fn int nt_get_generator(bigz_t p, factor_list_t *factors, bigz_t *g)
 * @brief Returns a random generator of Z_p*, given that p is prime. This is
 *  an implementation of algorithm 4.80 of Menezes et al. "Handbook of applied
 *  cryptography".
 *
 * @param[in] p A prime. Note that the algorithm won't work if p is not prime.
 * @param[in] factors The factors of (p-1).
 * @param[in,out] g The obtained generator.
 * 
 * @return IOK or IERROR
 */
int nt_get_generator(bigz_t p, factor_list_t *factors, bigz_t *g);

/** 
 * @fn int nt_get_elem_order(bigz_t n, bigz_t a, factor_list_t *factors, bigz_t *order)
 * @brief Calculates the order of element a within the cyclic group defined by n, 
 *  which has the specified factors. This is an implementation of algorithm 4.79 of 
 *  Menezes et al. "Handbook of applied cryptography".
 *
 * @param[in] n The modulo of the cyclic group.
 * @param[in] a The element whose order is to be returned.
 * @param[in] factors The prime factors of n.
 * @param[in,out] order Will be set to the order of a.
 * 
 * @return IOK or IERROR
 */
int nt_get_elem_order(bigz_t n, bigz_t a, factor_list_t *factors, bigz_t *order);

/** 
 * @fn int nt_get_safe_prime(uint64_t k, bigz_t p, bigz_t *a)
 * @brief Calculates a safe prime of k bits. This function is an implementation 
 *  of algorithm 4.86 of Menezes et al. "Handbook of applied cryptography".
 *
 * @param[in] k The desired length, in bits, of the generated safe prime.
 * @param[in,out] p Will be set to the generated prime.
 * @param[in,out] a When not NULL, will be set to a generator of the group
 *  of multiplicative inverses modulo p.
 * 
 * @todo The security of the primality test is fixed to PRIMALITY_TEST_SEC!
 *
 * @return IOK or IERROR
 */
int nt_get_safe_prime(uint64_t k, bigz_t p, bigz_t *a);

/** 
 * @fn int nt_get_germain_associate(bigz_t p, bigz_t g)
 * @brief Sets g to the Sophie-Germain prime "associated" to the safe prime p.
 *  The behavior of this function is undefined when p is not a safe prime.
 *
 * @param[in] p The safe prime.
 * @param[in,out] g The Sophie-Germain prime associated to p.
 * 
 * @return IOK
 */
int nt_get_germain_associate(bigz_t p, bigz_t g);


/** 
 * @fn int nt_get_random_group_element(bigz_t g, bigz_t n, bigz_t r)
 * @brief Generates a random element in the multiplicative cyclic group with
 *  modulus n and generator g.
 *
 * @param[in] g A generator of the group.
 * @param[in] n The modulus of the group.
 * @param[in,out] r Will be set to the randomly chosen element of the group.
 * 
 * @return IOK
 */
int nt_get_random_group_element(bigz_t g, bigz_t n, bigz_t r);

/** 
 * @fn int nt_PNT(bigz_t n, bigz_t pin)
 * @brief The Prime Number Theorem: sets pin to an approximate of the number
 *  of primes not bigger than n.
 *
 * @param[in] n The limit.
 * @param[in,out] pin Will be set to an approximate of the number of primes not
 *  bigger than n.
 * 
 * @return IOK or IERROR
 */
int nt_PNT(bigz_t n, bigz_t pin);

/** 
 * @fn int nt_get_n_primes_interval(bigz_t low, bigz_t up, bigz_t n)
 * @brief Uses the Prime Number Theorem to approximate the number of primes in a
 *  given interval.
 * 
 * @param[in] low The lower limit.
 * @param[in] up The upper limit.
 * @param[in,out] n An approximate to the number of primes in [low,up]
 * 
 * @return IOK or IERROR
 */
int nt_get_n_primes_interval(bigz_t low, bigz_t up, bigz_t n);

/** 
 * @fn int nt_get_nearest_power2(bigz_t n, bigz_t nearest2pow)
 * @brief Sets nearest2pow to the nearest power of two with respect to n.
 *
 * @param[in] n The number.
 * @param[in,out] nearest2pow Will be set to the nearest power of two with 
 *  respect to n.
 * 
 * @return IOK or IERROR
 */
int nt_get_nearest_power2(bigz_t n, bigz_t nearest2pow);

/** 
 * @fn int nt_get_greatest_power2_smaller_n(bigz_t n, bigz_t greatest2powsmallern)
 * @brief Gets the greatest power of two smaller than n.
 *
 * @param[in] n The number.
 * @param[in,out] greatest2powsmallern Will be set to the greatest power of two
 *  smaller than n.
 * 
 * @return IOK or IERROR
 */
int nt_get_greatest_power2_smaller_n(bigz_t n, bigz_t greatest2powsmallern);

#endif

/* nt.h ends here */
