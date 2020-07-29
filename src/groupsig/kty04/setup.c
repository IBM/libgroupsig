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
#include <math.h>

#include "kty04.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/mgr_key.h"
#include "groupsig/kty04/gml.h"
#include "math/nt.h"
#include "sys/mem.h"

/**
 * @def EPSILON_MIN
 * Defines the default minimum value for the epsilon modifier. It is a function
 * of K, the security parameter (see Lemma 9 of KTY04 for its requirements).
 * @see Demonstration in @todo I have it in paper!
 */
#define EPSILON_MIN(K) ((-1+SQRT2*K+SQRT2)/K)

/**
 * @def MU_MIN
 * Defines the default minimum value for the Mu modifier. It is a function
 * of K, the security parameter (see Lemma 9 of KTY04 for its requirements).
 * @see Demonstration in @todo I have it in paper!
 */
#define MU_MIN(K) (SQRT2*K+SQRT2+1)

/**
 * @def PRIMES_MIN
 * Defines the default minimum size for the (Sophie-Germain) primes of KTY04.
 * It is a function of MU_MIN. Note that we assume the use of the default spheres 
 * (those specified in KTY04).
 * Note: We force the two primes to be of the same size.
 */
#define PRIMES_MIN(K) (2*MU_MIN(K)+1)

/** 
 * @fn static int _setup_parameters_check(uint64_t k, uint64_t primesize, double epsilon)
 * @brief Checks the input parameters of the setup function
 *
 * @param[in] k The security parameter.
 * @param[in] primesize The Sophie Germain primes' size.
 * @param[in] epsilon The epsilon parameter for statistical indistinguishability.
 * 
 * @return IOK if the parameters are valid, IERROR otherwise
 */
static int _setup_parameters_check(uint64_t k, uint64_t primesize, double epsilon) {

  uint64_t primemin;

  if(!k || !primesize) {
    LOG_EINVAL(&logger, __FILE__, "_setup_parameters_check", __LINE__, LOGERROR);
    return IERROR;
  }
  
  /* Epsilon must be greater than the minimum epsilon */
  if(epsilon < EPSILON_MIN(k)) {
    fprintf(stderr, "Error: Invalid epsilon parameter (for k = %lu "
	    "it should be at least %.6f).\n",
	    k, EPSILON_MIN(k));
    LOG_EINVAL(&logger, __FILE__, "_setup_parameters_check", __LINE__, LOGERROR);    
    return IERROR;
  }
  
#ifdef DEBUG
  fprintf(stderr, "%s@%d: EPSILON_MIN(%lu): %.6f\n", __FILE__, __LINE__, k, EPSILON_MIN(k));
#endif

  /* Get the minimum acceptable prime size from the given security parameter:
     It depends on the security parameter k and the minimum radius of the three
     spheres. Since we use the default spheres (the ones specified in KTY04), 
     the minimum radius is ceil(log(p'*q'))/4-1. We use the PRIMES_MIN macro
     for this purpose.
   */
  primemin = (uint64_t) ceil(PRIMES_MIN(k));
  
  /* Check that the specified prime size is >= than the minimum. */
  if(primesize < primemin) {
    fprintf(stderr, "Error: The specified size for the Sophie Germain "
	    "primes is not enough (for k = %lu it should be at least %lu).\n",
	    k, primemin);
    LOG_EINVAL(&logger, __FILE__, "_setup_parameters_check", __LINE__, LOGERROR);
    return IERROR;
  }
  
#ifdef DEBUG
  fprintf(stderr, "%s@%d: PRIMES_MIN(%lu): %lu\n", __FILE__, __LINE__, k, (uint64_t) PRIMES_MIN(k));
#endif

  return IOK;

}

groupsig_config_t* kty04_config_init() {
  
  groupsig_config_t *cfg;

  if(!(cfg = (groupsig_config_t *) mem_malloc(sizeof(groupsig_config_t)))) {
    return NULL;
  }

  cfg->scheme = GROUPSIG_KTY04_CODE;
  if(!(cfg->config = (kty04_config_t *) mem_malloc(sizeof(kty04_config_t)))) {
    mem_free(cfg); cfg = NULL;
    return NULL;
  }

  KTY04_CONFIG_SET_DEFAULTS((kty04_config_t *) cfg->config);

  return cfg;

}

int kty04_config_free(groupsig_config_t *cfg) {

  if(!cfg) {
    return IOK;
  }

  mem_free(cfg->config); cfg->config = NULL;
  mem_free(cfg);
  return IOK;

}

int kty04_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, groupsig_config_t *config) {

  kty04_config_t *cfg;
  kty04_grp_key_t *gkey;
  kty04_mgr_key_t *mkey;
  bigz_t p, q, p1, q1, p1q1, n, r, x, y;
  factor_list_t factors;
  uint64_t k, primesize, epsilon, nu;
  int rc;

  if(!grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE ||
     !mgrkey || grpkey->scheme != GROUPSIG_KTY04_CODE ||
     !gml ||
     !config || config->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  cfg = (kty04_config_t *) config->config;
  k = cfg->security;
  primesize = cfg->primesize;
  epsilon = cfg->epsilon;

  if(_setup_parameters_check(k, primesize, epsilon) == IERROR) {
    return IERROR;
  }

  p=NULL; q=NULL; p1=NULL; q1=NULL; p1q1=NULL;
  n=NULL; r=NULL; x=NULL; y=NULL;
  rc = IOK;
  gkey = (kty04_grp_key_t *) grpkey->key;
  mkey = (kty04_mgr_key_t *) mgrkey->key;

  /* Generate the primes p and q, which must be safe primes */
  if(!(p = bigz_init())) GOTOENDRC(IERROR, kty04_setup);
  if(nt_get_safe_prime(primesize*2, p, NULL) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  
  /* p = 2*p1+1: p1 is p's  associated Sophie Germain prime */
  if(!(p1 = bigz_init())) GOTOENDRC(IERROR, kty04_setup);
  if(nt_get_germain_associate(p, p1) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  if(!(q = bigz_init())) GOTOENDRC(IERROR, kty04_setup);
  if(nt_get_safe_prime(primesize*2, q, NULL) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  /* q = 2*q1+1: q1 is q's associated Sophie Germain prime */
  if(!(q1 = bigz_init())) GOTOENDRC(IERROR, kty04_setup);
  if(nt_get_germain_associate(q, q1) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  /* nu = ceil(log(p1*q1)) */
  if(!(p1q1 = bigz_init())) GOTOENDRC(IERROR, kty04_setup);
  if(bigz_mul(p1q1, p1, q1) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  
  errno = 0;
  nu = bigz_sizeinbase(p1q1, 2);
  if(errno) GOTOENDRC(IERROR, kty04_setup);

#ifdef DEBUG
  fprintf(stderr, "%s@%d: nu: %lu\n", __FILE__, __LINE__, nu);
#endif  

  /** @todo In KTY04 they assume that nu is divisible by 4. We are ignoring it.
      May this lead to inconsistencies? */

  /** The three spheres sp_lambda, sp_m, sp_gamma must satisfy:
       S1. (min(sp_gamma))^2 > max(sp_gamma)
       S2. sp_m has size approximately equal to 2^ceil(nu/2)
       S3. mi(sp_gamma) > max(sp_m)*max(sp_lambda)+max(sp_lambda)+max(sp_m)

    We will use the spheres defined in Section 5 of KTY04, namely:
       inner_sp_lambda : S(2^(nu/4-1), 2^(nu/4-1))
       inner_sp_m      : S(2^(nu/2-1), 2^(nu/2-1))
       inner_sp_gamma  : S(2^(3*nu/4)+2^(nu/4-1), 2^(nu/4)-1)

    Therefore, the parameter nu = ceil(log(p1*q1)) suffices to define them.

    @todo A good extension could be to support other spheres!

   */

  /* Generate the elements of the public key, that is: a, a0, b, g, h and y
     chosen at random from QR(n), where n = pq */
  if(!(n = bigz_init())) GOTOENDRC(IERROR, kty04_setup);
  if(bigz_mul(n, p, q) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  /* QR(n) is a cyclic group: to obtain random elements in it, we get a generator, 
     and to get a generator, we need the prime factors of n, which are p and q. */  
  if(nt_factor_list_init(&factors) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  if(nt_factor_list_insert(&factors, p) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  if(nt_factor_list_insert(&factors, q) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  /* Get a generator */
  if(!(r = bigz_init())) GOTOENDRC(IERROR, kty04_setup);
  if(nt_get_generator(n, &factors, &r) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  if(nt_factor_list_free(&factors) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  /* r is a generator of the cyclic group of integers mod n, therefore,
     r^2 (mod n) is a generator of the cyclic group QR(n) */
  if(bigz_mul(r, r, r) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  if(bigz_mod(r, r, n) == IERROR) GOTOENDRC(IERROR, kty04_setup);
 
  /* Now choose the elements a, a0, b, g and h at random from QR(n) */
  if(bigz_set(gkey->n, n) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  if(nt_get_random_group_element(r, n, gkey->a) == IERROR ||
     nt_get_random_group_element(r, n, gkey->a0) == IERROR ||
     nt_get_random_group_element(r, n, gkey->b) == IERROR ||
     nt_get_random_group_element(r, n, gkey->g) == IERROR ||
     nt_get_random_group_element(r, n, gkey->h) == IERROR)
    GOTOENDRC(IERROR, kty04_setup);

  gkey->k = k;
  gkey->epsilon = epsilon;
  gkey->nu = nu;

  if(kty04_grp_key_set_spheres_std(gkey) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  /* Finally, we get randomly x from M, and make y=g^x (mod n). x will be the
     trapdoor for opening signatures*/
  if(!(x = bigz_init())) GOTOENDRC(IERROR, kty04_setup);
  if(sphere_get_random(gkey->M, x) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  if(bigz_powm(gkey->y, gkey->g, x, n) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  if(bigz_set(mkey->x, x) == IERROR) GOTOENDRC(IERROR, kty04_setup);

  /* Fill the private key elements */
  if(bigz_set(mkey->p, p) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  if(bigz_set(mkey->q, q) == IERROR) GOTOENDRC(IERROR, kty04_setup);
  mkey->nu = nu;

 kty04_setup_end:    
  
  /* Free resources and return */
  if(p) bigz_free(p);
  if(q) bigz_free(q);
  if(p1) bigz_free(p1);
  if(q1) bigz_free(q1); 
  if(p1q1) bigz_free(p1q1);
  if(n) bigz_free(n);
  if(r) bigz_free(r);
  if(x) bigz_free(x);
  if(y) bigz_free(y);

  return rc;

}

/* setup.c ends here */
