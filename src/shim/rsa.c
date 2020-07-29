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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "rsa.h"
#include "numbers.h"

int rsa_keypair_init(rsa_keypair_t *rsa) {

  if(!rsa) {
    fprintf(stderr, "Error in rsa_keypair_init (%d): %s\n",
	    __LINE__, strerror(errno));
    return IERROR;
  }

  mpz_init(rsa->p);
  mpz_init(rsa->q);
  mpz_init(rsa->n);
  mpz_init(rsa->phin);
  mpz_init(rsa->e);
  mpz_init(rsa->d);

  return IOK;

}

int rsa_keypair_free(rsa_keypair_t *rsa) {

  if(!rsa) {
    fprintf(stderr, "Error in rsa_keypair_free (%d): %s\n",
	    __LINE__, strerror(errno));
    return IERROR;
  }

  mpz_clear(rsa->p);
  mpz_clear(rsa->q);
  mpz_clear(rsa->n);
  mpz_clear(rsa->phin);
  mpz_clear(rsa->e);
  mpz_clear(rsa->d);

  return IOK;

}

int rsa_keypair_fprintf(FILE *fd, rsa_keypair_t *rsa) {

  char *sp, *sq, *sn, *sphin, *se, *sd;
  
  if(!rsa) {
    fprintf(stderr, "Error in rsa_keypair_fprintf (%d): %s\n",
	    __LINE__, strerror(errno));
    return IERROR;    
  }

  sp = mpz_get_str(NULL, 10, rsa->p);
  sq = mpz_get_str(NULL, 10, rsa->q);
  sn = mpz_get_str(NULL, 10, rsa->n);
  sphin = mpz_get_str(NULL, 10, rsa->phin);
  se = mpz_get_str(NULL, 10, rsa->e);
  sd = mpz_get_str(NULL, 10, rsa->d);
  
  fprintf(stderr, " CS97 RSA info:\n");
  fprintf(stderr, " -------------\n");
  fprintf(fd, 
	  "     p: %s\n"
	  "     q: %s\n"
	  "     n: %s\n"
	  "phi(n): %s\n"
	  "     e: %s\n"
	  "     d: %s\n\n",
	  sp,sq,sn,sphin,se,sd);

  free(sp); sp = NULL;
  free(sq); sq = NULL;
  free(sn); sn = NULL;
  free(sphin); sphin = NULL;
  free(se); se = NULL;
  free(sd); sd= NULL;

  return IOK;

}

int rsa_keygen(uint64_t primesize, rsa_keypair_t *rsa) {

  mpz_t p1, q1, e, gcd, d, t;

  /* Input parameters control */
  if(primesize <= 1 || !rsa) {
    fprintf(stderr, "Error in rsa_keygen (%d): %s\n", 
	    __LINE__, strerror(EINVAL));
    errno = EINVAL;
    return IERROR;
  }

  /** @todo Use strong primes! */

  /* Generate a random prime p of rouglhy primesize bits */
  if(numbers_mov97_alg462(primesize, &rsa->p, NULL) == IERROR) {
  /* if(numbers_genprime_random(primesize, &rsa->p) == IERROR) { */
    return IERROR;
  }

  /* Generate a random prime q, different from p, of rouglhy primesize bits */
  do {
    if(numbers_mov97_alg462(primesize, &rsa->q, NULL) == IERROR) {
      /* if(numbers_genprime_random(primesize, &rsa->q) == IERROR) { */
      return IERROR;
    }    
  } while(!mpz_cmp(rsa->p,rsa->q));

  /* Calculate the modulus */
  mpz_mul(rsa->n, rsa->p, rsa->q);

  /* Calculate phi(n) */
  mpz_init(p1);
  mpz_sub_ui(p1, rsa->p, 1);
  mpz_init(q1);
  mpz_sub_ui(q1, rsa->q, 1);
  mpz_mul(rsa->phin, p1, q1);

  /* Generate a random e less than phi(n) with gcd(e,phi(n)) = 1 */  
  mpz_init(e);
  mpz_init(gcd);
  mpz_init(d);
  mpz_init(t);
  do {
    mpz_urandomm(e, sysenv->gmp_rand, rsa->phin);
    mpz_add_ui(e,e,1);
    mpz_gcdext(gcd, d, t, e, rsa->phin);
  } while(mpz_cmp_ui(gcd, 1));

  /* It may happen that we obtain a negative d */
  if(mpz_sgn(d) < 0) {
    mpz_add(d, d, rsa->phin);
  }
  
  mpz_set(rsa->e, e);
  mpz_set(rsa->d, d);

  mpz_clear(p1);
  mpz_clear(q1);
  mpz_clear(gcd);
  mpz_clear(t);
  mpz_clear(e);
  mpz_clear(d);

  return IOK;

}

/* rsa.c ends here */
