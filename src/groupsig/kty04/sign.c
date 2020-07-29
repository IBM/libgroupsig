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

#include <stdlib.h>
#include <limits.h>
#include <openssl/sha.h> /** @todo This should not be! */

#include "kty04.h"
#include "groupsig/kty04/sphere.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/mem_key.h"
#include "groupsig/kty04/signature.h"
#include "bigz.h"

/* Private functions */

/** 
 * @fn static int _signature_get_objects(kty04_grp_key_t *grpkey, kty04_mem_key_t *memkey, 
 *                                       bigz_t r, bigz_t k, bigz_t kk, bigz_t *A)
 * @brief Gets the "default" objects for a KTY04 signature (that is, the ones 
 *  specified in the KTY04 paper, Section 8)
 * 
 * @param[in] grpkey The groupkey.
 * @param[in] memkey The signing member key.
 * @param[in] r The r free variable.
 * @param[in] k The k value.
 * @param[in] kk The k' value.
 * @param[in,out] A Will be set to the obtained objects.
 * 
 * @return IOK or IERROR
 */
static int _signature_get_objects(kty04_grp_key_t *grpkey, kty04_mem_key_t *memkey, bigz_t r,
				  bigz_t k, bigz_t kk, bigz_t *A) {

  bigz_t gr, hr, yr;

  if(!grpkey || !memkey || !r || !k || !kk || !A) {
    LOG_EINVAL(&logger, __FILE__, "_signature_get_objects", __LINE__, LOGERROR);
    return IERROR;
  }

  /* A3 = T2^-1 = (g^r)^(-1) */
  if(!(gr = bigz_init())) return IERROR;
  if(bigz_set(gr, grpkey->g) == IERROR) {
    bigz_free(gr);
    return IERROR;
  }

  if(bigz_powm(gr, gr, r, grpkey->n) == IERROR) {
    bigz_free(gr);
    return IERROR;
  }

  if(bigz_invert(gr, gr, grpkey->n) == IERROR) {
    bigz_free(gr);
    return IERROR;
  }

  /* A7 = T1^-1 = (A*y^r)^-1 */
  if(!(yr = bigz_init())) {
    bigz_free(gr);
    return IERROR;
  }
  
  if(bigz_powm(yr, grpkey->y, r, grpkey->n) == IERROR) {
    bigz_free(gr); bigz_free(yr);
    return IERROR;
  }

  if(bigz_mul(yr, yr, memkey->A) == IERROR) {
    bigz_free(gr); bigz_free(yr);
    return IERROR;
  }

  if(bigz_invert(yr, yr, grpkey->n) == IERROR) {
    bigz_free(gr); bigz_free(yr);
    return IERROR;
  }

  if(!(A[2] = bigz_init_set(gr))) {
    bigz_free(gr); bigz_free(yr);
    return IERROR;
  }

  if(!(A[6] = bigz_init_set(yr))) {
    bigz_free(gr); bigz_free(yr);
    return IERROR;
  }

  bigz_free(gr); bigz_free(yr);

  /* A1 = g */
  if(!(A[0] = bigz_init_set(grpkey->g))) return IERROR;

  /* A2 = h */
  if(!(A[1] = bigz_init_set(grpkey->h))) return IERROR;

  /* A4 = T5 = g^k */
  if(!(A[3] = bigz_init_set(grpkey->g))) return IERROR;
  
  if(bigz_powm(A[3], A[3], k, grpkey->n) == IERROR) return IERROR;

  /* A5 = T7 = g^kk */
  if(!(A[4] = bigz_init_set(grpkey->g))) return IERROR;
  if(bigz_powm(A[4], A[4], kk, grpkey->n) == IERROR) return IERROR;

  /* A6 = y */
  if(!(A[5] = bigz_init_set(grpkey->y))) return IERROR;

  /* A8 = a */
  if(!(A[7] = bigz_init_set(grpkey->a))) return IERROR;

  /* A9 = b */
  if(!(A[8] = bigz_init_set(grpkey->b))) return IERROR;

  /* A10 = a0 */
  if(!(A[9] = bigz_init_set(grpkey->a0))) return IERROR;

  /* A11 = T3 = g^e*h^r */
  if(!(hr = bigz_init())) return IERROR;
  if(bigz_powm(hr, grpkey->h, r, grpkey->n) == IERROR) return IERROR;
  if(!(A[10] = bigz_init_set(grpkey->g))) return IERROR;
  if(bigz_powm(A[10], A[10], memkey->e, grpkey->n) == IERROR) return IERROR;
  if(bigz_mul(A[10], A[10], hr) == IERROR) return IERROR;
  if(bigz_mod(A[10], A[10], grpkey->n) == IERROR) return IERROR;
  bigz_free(hr);

  /* A12 = T4 = g^(x*k) = A4^x */
  if(!(A[11] = bigz_init_set(A[3]))) return IERROR;
  if(bigz_powm(A[11], A[11], memkey->x, grpkey->n) == IERROR) return IERROR;

  /* A13 = T6 = g^(xx*kk) = A5^xx */
  if(!(A[12] = bigz_init_set(A[4]))) return IERROR;
  if(bigz_powm(A[12], A[12], memkey->xx, grpkey->n) == IERROR) return IERROR;

  return IOK;

}

/** 
 * @fn static int _signature_get_tw(uint64_t epsilon, uint64_t mu, uint64_t k, bigz_t t)
 * @brief Gets a tw random number using the specified paramters, and stores it
 *  in t.
 *
 * The resulting t will belong to the interval [-2^(epsilon*(mu+k), 2^(epsilon*(mu+k))].
 *
 * @param[in] epsilon The epsilon parameter.
 * @param[in] mu The mu parameter.
 * @param[in] k The k parameter.
 * @param[in,out] t Will be set to the randomly generated tw.
 * 
 * @return IOK or IERROR
 */
static int _signature_get_tw(uint64_t epsilon, uint64_t mu, uint64_t k, bigz_t t) {

  bigz_t r;
  uint64_t exp, inner_mu;

  if(!t) {
    LOG_EINVAL(&logger, __FILE__, "_signature_get_tw", __LINE__, LOGERROR);
    return IERROR;
  }

  /* The mu we receive here is the mu of the "original" sphere, however, we want
     the mu of its associated inner sphere, which is given by (mu-2)/epsilon-k */
  inner_mu = mu - 2;
  inner_mu /= epsilon;
  inner_mu -= k;

  /* We want a number in +-{0,1}^(epsilon*(inner_mu+k)) */

  /* Calculate the exponent:
     Hack: Instead of getting a random number in [0,2^exp-1] and then randomly
     choosing the sign, we get a random number in [0,2^(exp+1)-1], use the LSbit to
     determine the sign, and divide it by 2 to discard it. This will get us
     more easily a random number in [-2^(epsilon*(inner_mu+k)), 2^(epsilon*(inner_mu+k))].
   */
  exp = epsilon*(k+inner_mu)+1;

  /* Get a number in [0,2^(exp+1)-1] */
  if(!(r = bigz_init())) return IERROR;
  if(bigz_urandomb(r, sysenv->big_rand, exp) == IERROR) {
    bigz_free(r); 
    return IERROR;
  }

  /* Use the LSbit to determine the sign: if 1, make r negative */
  errno = 0;
  if(bigz_tstbit(r, 0)) {
    if(errno || bigz_neg(r, r) == IERROR) { bigz_free(r); return IERROR; }
  }

  /* Discard the LSbit */
  if(bigz_tdiv_ui(r, NULL, r, 2) == IERROR) {
    bigz_free(r);
    return IERROR;
  }

  if(bigz_set(t, r) == IERROR) return IERROR;
  bigz_free(r);

  return IOK;
  
}

/** 
 * @fn static int _signature_get_tws(gr_pkey_t *grpkey, bigz_t *tw)
 * @brief Gets the random tw's choosing from the corresponding spheres.
 *
 * @param[in] grpkey The group key.
 * @param[in,out] tw Will be set to the generated tw's.
 * 
 * @return IOK or IERROR
 */
static int _signature_get_tws(kty04_grp_key_t *grpkey, bigz_t *tw) {

  sphere_t *sp_prod;
  size_t mu_prod;

  if(!grpkey || !tw) {
    LOG_EINVAL(&logger, __FILE__, "_signature_get_tws", __LINE__, LOGERROR);
    return IERROR;
  }

  /* x and xx belong to inner_lambda, thererfore, we use lambda's mu = nu/4-1 for 
     tw[0] and tw[1] */
  if(!(tw[0] = bigz_init())) return IERROR;
  if(_signature_get_tw(grpkey->epsilon, grpkey->nu/4-1, grpkey->k, tw[0]) == IERROR) {
    return IERROR;
  }
  
  if(!(tw[1] = bigz_init())) return IERROR;
  if(_signature_get_tw(grpkey->epsilon, grpkey->nu/4-1, grpkey->k, tw[1]) == IERROR) {
    return IERROR;
  }
  
  /* e belongs to inner_gamma, therefore, we use gamma's mu = nu/4-1 for tw[2] */
  if(!(tw[2] = bigz_init())) return IERROR;
  if(_signature_get_tw(grpkey->epsilon, grpkey->nu/4-1, grpkey->k, tw[2]) == IERROR) {
    return IERROR;
  }

  /* r belongs to inner_M, therefore, we use M's mu = nu/2-1 for tw[3]
     @see todo(1) in kty04_signature_sign  */
  if(!(tw[3] = bigz_init())) return IERROR;
  if(_signature_get_tw(grpkey->epsilon, grpkey->nu/2-1, grpkey->k, tw[3]) == IERROR) {
    return IERROR;
  }

  /* hh = e*r, where e belongs to inner gamma and r belongs to inner M. Therefore,
     hh belongs to the product of inner gamma and inner M. We need to get the 
     radius of the product of both spheres (actually, its log2).
  */
  if(!(sp_prod = sphere_init())) return IERROR;
  if(sphere_get_product_spheres(grpkey->inner_gamma, grpkey->inner_M, 
				sp_prod) == IERROR) {
    sphere_free(sp_prod);
    return IERROR;
  }

  /** @todo Although in the KTY04 shcheme, all the spheres has centers and radius
      that are powers of 2, their product need not be an exact power of 2. Here, we
      round the log2 to the immediatly bigger integer (if > 0) or to the immediatly
      smaller (if < 0). Does this have some impact in the method? */
  errno = 0;
  mu_prod = bigz_sizeinbase(sp_prod->radius, 2);
  if(errno) {
    sphere_free(sp_prod);
    return IERROR;
  }
  
  if(sphere_free(sp_prod) == IERROR) {
    return IERROR;
  }

  if(!(tw[4] = bigz_init())) return IERROR;
  if(_signature_get_tw(grpkey->epsilon, mu_prod, grpkey->k, tw[4]) == IERROR) {
    return IERROR;
  }

  return IOK;
  
}

/** 
 * @fn static int _signature_get_Bs(bigz_t *A, bigz_t *tw, bigz_t n, bigz_t *B)
 * @brief Calculates the B's of the KTY04 signature scheme
 *
 * @param[in] A The objects, obtained using _kty04_signature_get_objects.
 * @param[in] tw The tw's.
 * @param[in] n The group modulus.
 * @param[in,out] B Will be set to the obtained B's.
 * 
 * @return IOK or IERROR
 */
static int _signature_get_Bs(bigz_t *A, bigz_t *tw, bigz_t n, bigz_t *B) {
  
  bigz_t a2t4, a3t3, a7t3, a8t1, a9t2;

  if(!A || !tw || !n || !B) {
    LOG_EINVAL(&logger, __FILE__, "_signature_get_BS", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Relation 1: B1 = A1^tw4 */
  if(!(B[0] = bigz_init())) return IERROR;
  if(bigz_powm(B[0], A[0], tw[3], n) == IERROR) return IERROR;

  /* Relation 2: B2 = A1^tw3*A2^tw4 */
  if(!(B[1] = bigz_init())) return IERROR;
  if(!(a2t4 = bigz_init())) return IERROR;
  if(bigz_powm(a2t4, A[1], tw[3], n) == IERROR) { bigz_free(a2t4); return IERROR; }
  if(bigz_powm(B[1], A[0], tw[2], n) == IERROR) { bigz_free(a2t4); return IERROR; }
  if(bigz_mul(B[1], B[1], a2t4) == IERROR) { bigz_free(a2t4); return IERROR; }
  if(bigz_mod(B[1], B[1], n) == IERROR) { bigz_free(a2t4); return IERROR; }
  bigz_free(a2t4);

  /* Relation 3: B3 = A1^tw5*A3^t3 */
  if(!(B[2] = bigz_init())) return IERROR;
  if(!(a3t3 = bigz_init())) return IERROR;
  if(bigz_powm(a3t3, A[2], tw[2], n) == IERROR)  { bigz_free(a3t3); return IERROR; }
  if(bigz_powm(B[2], A[0], tw[4], n) == IERROR) { bigz_free(a3t3); return IERROR; }
  if(bigz_mul(B[2], B[2], a3t3) == IERROR) { bigz_free(a3t3); return IERROR; }
  if(bigz_mod(B[2], B[2], n) == IERROR) { bigz_free(a3t3); return IERROR; }
  bigz_free(a3t3);

  /* Relation 4: B4 = A4^tw1 */
  if(!(B[3] = bigz_init())) return IERROR;
  if(bigz_powm(B[3], A[3], tw[0], n) == IERROR) return IERROR;

  /* Relation 5: B5 = A5^tw2 */
  if(!(B[4] = bigz_init())) return IERROR;
  if(bigz_powm(B[4], A[4], tw[1], n) == IERROR) return IERROR;

  /* Relation 6: B6 = A6^tw5*A7^tw3*A8^tw1*A9^tw2 */
  if(!(B[5] = bigz_init())) return IERROR;
  if(!(a7t3 = bigz_init())) return IERROR;
  if(bigz_powm(a7t3, A[6], tw[2], n) ==  IERROR) return IERROR;
  if(!(a8t1 = bigz_init())) { bigz_free(a7t3); return IERROR; }
  if(bigz_powm(a8t1, A[7], tw[0], n) == IERROR) { 
    bigz_free(a7t3); bigz_free(a8t1); 
    return IERROR; 
  }

  if(!(a9t2 = bigz_init())) {
    bigz_free(a3t3); bigz_free(a8t1);
    bigz_free(a9t2);
    return IERROR;
  }

  if(bigz_powm(a9t2, A[8], tw[1], n) == IERROR) {
    bigz_free(a3t3); bigz_free(a8t1);
    bigz_free(a9t2);
    return IERROR;    
  }

  if(bigz_powm(B[5], A[5], tw[4], n) == IERROR) {
    bigz_free(a3t3); bigz_free(a8t1);
    bigz_free(a9t2);
    return IERROR;  
  }

  if(bigz_mul(B[5], B[5], a7t3) == IERROR) {
    bigz_free(a3t3); bigz_free(a8t1);
    bigz_free(a9t2);
    return IERROR;  
  }

  if(bigz_mul(B[5], B[5], a8t1) == IERROR) {
    bigz_free(a3t3); bigz_free(a8t1);
    bigz_free(a9t2);
    return IERROR;  
  }
  
  if(bigz_mul(B[5], B[5], a9t2) == IERROR) {
    bigz_free(a3t3); bigz_free(a8t1);
    bigz_free(a9t2);
    return IERROR;  
  }
  
  if(bigz_mod(B[5], B[5], n) == IERROR) {
    bigz_free(a3t3); bigz_free(a8t1);
    bigz_free(a9t2);
    return IERROR;  
  }

  bigz_free(a7t3);
  bigz_free(a8t1);
  bigz_free(a9t2);

  return IOK;

}

/** 
 * @fn static int _signature_get_sws(bigz_t *tw, bigz_t c, bigz_t x, bigz_t xx, 
 *				    bigz_t e, bigz__t r, bigz_t hh, 
 *				    kty04_grp_key_t *grpkey, bigz_t *sw)
 * @brief Sets sw to the sw's used in the KTY04 signature scheme.
 * 
 * @param[in] tw The tw's obtained with _kty04_signature_get_tws.
 * @param[in] c The c obtained as hash(message, tw[1], ... , tw[r]).
 * @param[in] x The x free variable.
 * @param[in] xx The x' free variable.
 * @param[in] e The e free variable.
 * @param[in] r The r free variable.
 * @param[in] hh The h' free variable.
 * @param[in] grpkey The KTY04 group key.
 * @param[in,out] sw Will be set to the obtained sw's
 * 
 * @return IOK or IERROR
 */
static int _signature_get_sws(bigz_t *tw, bigz_t c, bigz_t x, bigz_t xx, 
			      bigz_t e, bigz_t r, bigz_t hh, 
			      kty04_grp_key_t *grpkey, bigz_t *sw) {
  sphere_t *sp_prod;
  bigz_t sub;

  if(!tw || !c || !x || !xx || !e || !r || !hh || !grpkey || !sw) {
    LOG_EINVAL(&logger, __FILE__, "_signature_get_sws", __LINE__, LOGERROR);
    return IERROR;
  }
  
  if(!(sub = bigz_init())) return IERROR;

  /* sw1: tw1 - c*(x - inner_lambda->center) */
  if(!(sw[0] = bigz_init())) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sub, x, grpkey->inner_lambda->center) == IERROR) { 
    bigz_free(sub); 
    return IERROR;
  }

  if(bigz_mul(sub, sub, c) == IERROR) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sw[0], tw[0], sub) == IERROR) { bigz_free(sub); return IERROR; }

  /* sw2: tw2 - c*(xx - inner_lambda->center) */
  if(!(sw[1] = bigz_init())) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sub, xx, grpkey->inner_lambda->center) == IERROR) { 
    bigz_free(sub); 
    return IERROR;
  }

  if(bigz_mul(sub, sub, c) == IERROR) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sw[1], tw[1], sub) == IERROR) { bigz_free(sub); return IERROR; }

  /* sw3: tw3 - c*(e - inner_gamma->center) */
  if(!(sw[2] = bigz_init())) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sub, e, grpkey->inner_gamma->center) == IERROR) { 
    bigz_free(sub); 
    return IERROR;
  }

  if(bigz_mul(sub, sub, c) == IERROR) { 
    bigz_free(sub); 
    return IERROR;
  }

  if(bigz_sub(sw[2], tw[2], sub) == IERROR) { bigz_free(sub); return IERROR; }

  /* sw4: tw4 - c*(r - inner_m->center) */
  if(!(sw[3] = bigz_init())) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sub, r, grpkey->inner_M->center) == IERROR) { 
    bigz_free(sub); 
    return IERROR;
  }

  if(bigz_mul(sub, sub, c) == IERROR) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sw[3], tw[3], sub) == IERROR) { bigz_free(sub); return IERROR; }

  /* sw5: tw5 - c*(hh - inner_gamma->center) */

  /* The exponent of sw5 is obtained from the product of the spheres gamma and M */
  if(!(sp_prod = sphere_init())) { bigz_free(sub); return IERROR; }
  if(sphere_get_product_spheres(grpkey->inner_gamma, grpkey->inner_M, 
				sp_prod) == IERROR) {   
    bigz_free(sub);
    sphere_free(sp_prod);
    return IERROR;
  }

  if(!(sw[4] = bigz_init())) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sub, hh, sp_prod->center) == IERROR) { bigz_free(sub); return IERROR; }
  if(bigz_mul(sub, sub, c) == IERROR) { bigz_free(sub); return IERROR; }
  if(bigz_sub(sw[4], tw[4], sub) == IERROR) { bigz_free(sub); return IERROR; }

  bigz_free(sub);
  if(sphere_free(sp_prod) == IERROR) {
    return IERROR;
  }
  
  return IOK;

}

int kty04_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey, unsigned int seed) {

  /* Here we won't follow the typical C programming conventions for naming variables.
     Instead, we will name the variables as in the KTY04 paper (with the exception 
     of doubling a letter when a ' is used, e.g. k' ==> kk). Auxialiar variables 
     that are not specified in the paper but helpful or required for its 
     implementation will be named aux_<name> */

  kty04_grp_key_t *gkey;
  kty04_mem_key_t *mkey;
  kty04_signature_t *kty04_sig;
  byte_t aux_sc[SHA_DIGEST_LENGTH+1];
  bigz_t k, kk, r, hh, *A, *tw, *B, c, *sw;
  SHA_CTX aux_sha;
  uint32_t aux_i;
  char *aux_sB, *aux_sA;
  int rc;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_KTY04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Used to re-generate the same signature (e.g., for creating pseudonyms) */
  if(seed != UINT_MAX) {
    sysenv_reseed(seed);
  }

  k=NULL; kk=NULL; r=NULL; hh=NULL; A=NULL; tw=NULL; B=NULL; c=NULL; sw=NULL;
  rc = IOK;

  gkey = (kty04_grp_key_t *) grpkey->key;
  mkey = (kty04_mem_key_t *) memkey->key;
  kty04_sig = (kty04_signature_t *) sig->sig;

  /* 0) Get the relation set variables and objects */

  /* Get the xw's: (the variables)
        - x and x' are the x and xx fields of the memkey 
	- e is the e field of the memkey
	- r, k and k' \in_R inner_M (k and k' are not really xw's) 
	- h' = e*r
  */
  /** @note (1) In the paper, r, k and k' are chosen from M, and not M_epsilon^k.
      I think it is an errata, since we are proving that they belong to M, and
      therefore, they must be chosen from M's inner sphere (also, all the other
      free variables are chosen from the inner spheres of lambda and gamma). */
  if(!(r = bigz_init())) {
    return IERROR;
  }

  if(sphere_get_random(gkey->inner_M, r) == IERROR) 
    GOTOENDRC(IERROR, kty04_sign);

  if(!(k = bigz_init())) GOTOENDRC(IERROR, kty04_sign);

  if(sphere_get_random(gkey->inner_M, k) == IERROR)
    GOTOENDRC(IERROR, kty04_sign);

  if(!(kk = bigz_init())) GOTOENDRC(IERROR, kty04_sign);
  if(sphere_get_random(gkey->inner_M, kk) == IERROR) 
    GOTOENDRC(IERROR, kty04_sign);

  if(!(hh = bigz_init())) GOTOENDRC(IERROR, kty04_sign);
  if(bigz_mul(hh, mkey->e, r) == IERROR) GOTOENDRC(IERROR, kty04_sign);

  /* Get the relation set objects */
  if(!(A = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->m))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_sign", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_sign);
  }
  
  if(_signature_get_objects(gkey, mkey, r, k, kk, A) == IERROR) {
    GOTOENDRC(IERROR, kty04_sign);
  }
  
  /* 1) Get the tw[1] ... tw[r] */
  if(!(tw = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->r))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_sign", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_sign);
  }

  if(_signature_get_tws(gkey, tw) == IERROR) {
    GOTOENDRC(IERROR, kty04_sign);
  }

  /* 2) Calculate the Bi's  */
  if(!(B = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->z))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_sign", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_sign);
  }
  
  if(_signature_get_Bs(A, tw, gkey->n, B) == IERROR) {
    GOTOENDRC(IERROR, kty04_sign);
  }

  /* 3) Calculate c = hash(msg | B[1] | ... | B[z] | A[1] | ... | A[m]) */

  /* Initialize the hashing environment */
  /** @todo Use EVP_* instead of SHA1_* */
  if(!SHA1_Init(&aux_sha)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_sign", __LINE__, EDQUOT,
		      "SHA1_Init", LOGERROR);
    GOTOENDRC(IERROR, kty04_sign);
  }

  /* Put the message into the hash */
  if(!SHA1_Update(&aux_sha, msg->bytes, msg->length)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_sign", __LINE__, EDQUOT,
		      "SHA1_Update", LOGERROR);
    GOTOENDRC(IERROR, kty04_sign);
  }

  for(aux_i=0; aux_i<kty04_sig->z; aux_i++) {

    /* Put the i-th element of the array */
    if(!(aux_sB = bigz_get_str(10, B[aux_i]))) GOTOENDRC(IERROR, kty04_sign);
    if(!SHA1_Update(&aux_sha, aux_sB, strlen(aux_sB))) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_sign", __LINE__, EDQUOT,
			"SHA1_Update", LOGERROR);
      GOTOENDRC(IERROR, kty04_sign);
    }

    free(aux_sB); aux_sB = NULL;

  }

  for(aux_i=0; aux_i<kty04_sig->m; aux_i++) {

    /* Put the i-th element of the array */
    if(!(aux_sA = bigz_get_str(10, A[aux_i]))) GOTOENDRC(IERROR, kty04_sign);
    if(!SHA1_Update(&aux_sha, aux_sA, strlen(aux_sA))) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_sign", __LINE__, EDQUOT,
			"SHA1_Update", LOGERROR);
      GOTOENDRC(IERROR, kty04_sign);
    }

    free(aux_sA); aux_sA = NULL;

  }

  /* Calculate the hash */
  memset(aux_sc, 0, SHA_DIGEST_LENGTH+1);
  if(!SHA1_Final(aux_sc, &aux_sha)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_sign", __LINE__, EDQUOT,
			"SHA1_Final", LOGERROR);
      GOTOENDRC(IERROR, kty04_sign);
  }

  /* Now, we have to get c = h(message,B[1],...,B[z],A[1]...,A[m]) as an mpz */
  if(!(c = bigz_import(aux_sc,SHA_DIGEST_LENGTH))) GOTOENDRC(IERROR, kty04_sign);
  if(bigz_set(kty04_sig->c, c) == IERROR) GOTOENDRC(IERROR, kty04_sign);

  /* For the calculations of the sw's we are only interested in the k LSbits of c. */
  errno = 0;
  for(aux_i=gkey->k; aux_i<bigz_sizeinbase(c, 2); aux_i++) {
    if(errno) GOTOENDRC(IERROR, kty04_sign);
    if(bigz_clrbit(c, aux_i) == IERROR) GOTOENDRC(IERROR, kty04_sign);
  }
  
  /* 4) Set sw[i] = tw[i] - c * (xw - 2^lw) */
  if(!(sw = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->r))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_sign", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_sign);
  }

  if(_signature_get_sws(tw, c, mkey->x, mkey->xx,
			mkey->e, r, hh, gkey, 
			sw) == IERROR) {
    GOTOENDRC(IERROR, kty04_sign);
  }

  /* Free resources and exit */
 kty04_sign_end:

  /* If received a seed, reseed randomly */
  if(seed != UINT_MAX) {
    sysenv_reseed(UINT_MAX);
  }

  if(r) bigz_free(r);
  if(k) bigz_free(k);
  if(kk) bigz_free(kk);
  if(hh) bigz_free(hh);
  if(c) bigz_free(c);

  /* if there's been no error, update the As vector */
  if(A) {
    for(aux_i=0; aux_i<kty04_sig->m; aux_i++) {
      if(bigz_set(kty04_sig->A[aux_i], A[aux_i]) == IERROR) rc = IERROR;
      bigz_free(A[aux_i]);
    }
    free(A); A = NULL;
  }

  if(B) {
    for(aux_i=0; aux_i<kty04_sig->z; aux_i++) {
      /* if(bigz_set(kty04_sig->B[aux_i], B[aux_i]) == IERROR) rc = IERROR; */
      bigz_free(B[aux_i]);
    }
    free(B); B = NULL;
  }

  if(tw) {
    for(aux_i=0; aux_i<kty04_sig->r; aux_i++)  bigz_free(tw[aux_i]);
    free(tw); tw = NULL;
  }

  /* If there's been no error, update the sws vector */
  if(sw) {
    for(aux_i=0; aux_i<kty04_sig->r; aux_i++) {
      if(bigz_set(kty04_sig->sw[aux_i], sw[aux_i]) == IERROR) rc = IERROR;
      bigz_free(sw[aux_i]);
    }
    free(sw); sw = NULL;
  }

  return rc;

}

/* sign.c ends here */
