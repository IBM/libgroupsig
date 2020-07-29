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

#ifndef _RSA_H
#define _RSA_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"

/**
 * @struct rsa_keypair_t
 * @brief An RSA cryptosystem structure.
 */
typedef struct {
  mpz_t p; /**< The p prime */
  mpz_t q; /**< The q prime */
  mpz_t n; /**< The modulus */
  mpz_t phin; /**< phi(n) */
  mpz_t e; /**< Public exponent */
  mpz_t d; /**< Private exponent */
} rsa_keypair_t;

/** 
 * @fn int rsa_keypair_init(rsa_keypair_t *rsa)
 * @brief Initializes a rsa keypair structure.
 * 
 * @param[in,out] rsa A pointer to the structure
 * 
 * @return IOK or IERROR
 */
int rsa_keypair_init(rsa_keypair_t *rsa);

/** 
 * @fn int rsa_keypair_free(rsa_keypair_t *rsa)
 * @brief Frees the memory allocated forthe received rsa keypair structure.
 * 
 * @param[in,out] rsa A pointer to the structure to free.
 * 
 * @return IOK or IERROR
 */
int rsa_keypair_free(rsa_keypair_t *rsa);

/** 
 * @fn int rsa_keypair_fprintf(FILE *fd, rsa_keypair_t *rsa)
 * @brief Prints the keypair into the specified ouptut.
 *
 * @param[in] fd The file descriptor to print to.
 * @param[in] rsa The key to print.
 * 
 * @return IOK or IERROR
 */
int rsa_keypair_fprintf(FILE *fd, rsa_keypair_t *rsa);

/** 
 * @fn int rsa_keygen(uint64_t primesize, rsa_keys_t *rsa)
 * @brief Generates a private-public RSA keypair.
 *
 * The generated keypair is special in the sense that the generated primes p and q
 * are of the shape t=2Rt'+1, where t' is also prime and R is some composite of
 * known factorization.
 *
 * @param[in] primesize The desired (approximate) size, in bits, of the RSA primes.
 * @param rsa The structure to store the keypair in.
 * 
 * @return IOK or IERROR
 */
int rsa_keygen(uint64_t primesize, rsa_keypair_t *rsa);

#endif /* _RSA_H */

/* rsa.h ends here */
