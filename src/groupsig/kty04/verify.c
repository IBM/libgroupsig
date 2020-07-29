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
#include <openssl/sha.h> /** @todo This should not be! */

#include "kty04.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/signature.h"
#include "bigz.h"

/* Private functions */

/** 
 * @fn static int _signature_check_sw_intervals(kty04_grp_key_t *grpkey, kty04_signature_t *sig, 
 *			                    uint8_t *fail)
 * @brief Checks the interval of the sw elements of a KTY04 signature.
 * 
 * @param[in] grpkey The group key.
 * @param[in] sig The signature.
 * @param[in,out] fail Will be set to 0 if the sw's are ok, to 1 otherwise.
 * 
 * @return IOK or IERROR
 */
static int _signature_check_sw_intervals(kty04_grp_key_t *grpkey, kty04_signature_t *sig, 
					 uint8_t *fail) {

  bigz_t lambda_min, lambda_max, m_min, m_max, gamma_min, gamma_max, prod_min, prod_max;
  uint64_t exp_lambda, exp_m, /* exp_gamma, */ exp_prod, mu_prod;
  sphere_t *sp_prod;
  int rc;

  if(!grpkey || !sig || !fail) {
    fprintf(stderr, "Error in _kty04_signature_check_sw_intervals (%d): %s\n", __LINE__, 
	    strerror(EINVAL));
    errno = EINVAL;
    return IERROR;
  }

  sp_prod = NULL;
  lambda_min=NULL; lambda_max=NULL; m_min=NULL; m_max=NULL;
  gamma_min=NULL; gamma_max=NULL; prod_min=NULL; prod_max=NULL;
  rc = IOK;

  /* Get the expected intervals */

  /* The exponent of sw[4] is obtained from the product of the spheres gamma and M */
  if(!(sp_prod = sphere_init())) return IERROR;
  if(sphere_get_product_spheres(grpkey->inner_gamma, grpkey->inner_M, 
				sp_prod) == IERROR) {   
    sphere_free(sp_prod);
    return IERROR;
  }
  
  /** @todo Although in the KTY04 shcheme, all the spheres have centers and radius
      that are powers of 2, their product need not be an exact power of 2. Here, we
      round the log2 to the immediatly bigger integer (if > 0) or to the immediatly
      smaller (if < 0). Does this have some impact in the method? */
  errno = 0;
  mu_prod = bigz_sizeinbase(sp_prod->radius, 2);
  if(errno) { sphere_free(sp_prod); return IERROR; }

  if(sphere_free(sp_prod) == IERROR) 
    GOTOENDRC(IERROR, _signature_check_sw_intervals);

  exp_lambda = grpkey->epsilon*((grpkey->nu/4-1)+grpkey->k)+1;
  exp_m = grpkey->epsilon*((grpkey->nu/2-1)+grpkey->k)+1;
  /* exp_gamma = exp_lambda; */
  exp_prod = grpkey->epsilon*(mu_prod+grpkey->k)+1;

  if(!(lambda_max = bigz_init())) 
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(bigz_ui_pow_ui(lambda_max, 2, exp_lambda) == IERROR) 
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(bigz_sub_ui(lambda_max, lambda_max, 1) == IERROR) 
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(!(lambda_min = bigz_init())) 
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(bigz_neg(lambda_min, lambda_max) == IERROR) 
    GOTOENDRC(IERROR, _signature_check_sw_intervals);

  if(!(m_max = bigz_init()))
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(bigz_ui_pow_ui(m_max, 2, exp_m) == IERROR)
    GOTOENDRC(IERROR, _signature_check_sw_intervals);    
  if(bigz_sub_ui(m_max, m_max, 1) == IERROR)
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(!(m_min = bigz_init()))
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(bigz_neg(m_min, m_max) == IERROR)
    GOTOENDRC(IERROR, _signature_check_sw_intervals);

  if(!(gamma_max = bigz_init_set(lambda_max)))
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(!(gamma_min = bigz_init_set(lambda_min)))
    GOTOENDRC(IERROR, _signature_check_sw_intervals);

  if(!(prod_max = bigz_init()))
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(bigz_ui_pow_ui(prod_max, 2, exp_prod) == IERROR)
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(bigz_sub_ui(prod_max, prod_max, 1) == IERROR)
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(!(prod_min = bigz_init()))
    GOTOENDRC(IERROR, _signature_check_sw_intervals);
  if(bigz_neg(prod_min, prod_max) == IERROR)
    GOTOENDRC(IERROR, _signature_check_sw_intervals);

  /* sw1: tw1 - c*(x - inner_lambda->center), therefore, sw1 must belong to
     +-2^epsilon*(mu_lambda+k)+1 */
  errno = 0;
  if(bigz_cmp(sig->sw[0], lambda_min) < 0 || 
     bigz_cmp(sig->sw[0], lambda_max) > 0) {
    if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);
    *fail = 1;
    return IOK;
  }

  if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);

  /* sw2: tw2 - c*(xx - inner_lambda->center), therefore, sw2 must belong to
     +-2^epsilon*(mu_lambda+k)+1 */
  if(bigz_cmp(sig->sw[1], lambda_min) < 0 || bigz_cmp(sig->sw[1], lambda_max) > 0) {
    if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);
    *fail = 1;
    return IOK;
  }

  if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);

  /* sw3: tw3 - c*(e - inner_gamma->center), therefore, sw3 must belong to
     +-2^epsilon*(mu_gamma+k)+1 */
  if(bigz_cmp(sig->sw[2], gamma_min) < 0 || bigz_cmp(sig->sw[2], gamma_max) > 0) {
    if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);
    *fail = 1;
    return IOK;
  }

  if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);

  /* sw4: tw4 - c*(r - inner_m->center), therefore, sw4 must belong to
     +-2^epsilon*(mu_m+k)+1 */
  if(bigz_cmp(sig->sw[3], m_min) < 0 || bigz_cmp(sig->sw[3], m_max) > 0) {
    if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);
    *fail = 1;
    return IOK;
  }

  if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);

  /* sw5: tw5 - c*(hh - inner_gamma->center), therefore, sw5 must belong to
     +-2^epsilon*(mu_prod+k)+1 */
  if(bigz_cmp(sig->sw[4], prod_min) < 0 || bigz_cmp(sig->sw[4], prod_max) > 0) {
    if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);
    *fail = 1;
    return IOK;
  }

  if(errno) GOTOENDRC(IERROR, _signature_check_sw_intervals);

 _signature_check_sw_intervals_end:

  if(lambda_min) bigz_free(lambda_min);
  if(lambda_max) bigz_free(lambda_max);
  if(m_min) bigz_free(m_min);
  if(m_max) bigz_free(m_max);
  if(gamma_min) bigz_free(gamma_min);
  if(gamma_max) bigz_free(gamma_max);
  if(prod_min) bigz_free(prod_min); 
  if(prod_max) bigz_free(prod_max);

  if(rc == IOK) *fail = 0;

  return rc;

}

static int _signature_recover_Bs(kty04_grp_key_t *grpkey, kty04_signature_t *sig, bigz_t *B) {

  sphere_t *sp_prod;
  bigz_t c, aux, aux2;
  uint32_t i, sc;
  int rc;

  if(!grpkey || !sig || !B) {
    LOG_EINVAL(&logger, __FILE__, "_signature_recover_Bs", __LINE__, LOGERROR);
    return IERROR;
  }

  c = NULL; aux = NULL; aux2 = NULL;
  rc = IOK;

  /* To recover the B's we only need the k LSbits of c */
  if(!(c = bigz_init_set(sig->c))) GOTOENDRC(IERROR, _signature_recover_Bs);
  errno = 0;
  sc = bigz_sizeinbase(c, 2);
  if(errno) GOTOENDRC(IERROR, _signature_recover_Bs);
  for(i=grpkey->k; i<sc; i++) {
    errno = 0;
    bigz_clrbit(c, i);
    if(errno) GOTOENDRC(IERROR, _signature_recover_Bs);
  }

  /* We will also need the product of spheres inner_gamma and inner_M */
  if(!(sp_prod = sphere_init())) GOTOENDRC(IERROR, _signature_recover_Bs);
  if(sphere_get_product_spheres(grpkey->inner_gamma, grpkey->inner_M, 
				sp_prod) == IERROR) {   
    sphere_free(sp_prod);
    return IERROR;
  }

  if(!(aux = bigz_init())) GOTOENDRC(IERROR, _signature_recover_Bs);
  if(!(aux2 = bigz_init())) GOTOENDRC(IERROR, _signature_recover_Bs);

  /* B[0] = A[0]^sw[3]*(A[0]^(2l_3)*A[2])^(-c) */
  if(bigz_powm(aux, sig->A[0], sig->sw[3], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[0], grpkey->inner_M->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux2, aux2, sig->A[2]) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_invert(aux2, aux2, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, aux2, c, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mod(B[0], aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);

  /* B[1] = A[0]^sw[2]*A[1]^sw[3]*A[10]^c*(A[0]^(2l_2)*A[1]^(2l_3)^(-c) */
  if(bigz_powm(aux, sig->A[0], grpkey->inner_gamma->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[1], grpkey->inner_M->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_invert(aux, aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux, aux, c, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[10], c, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[0], sig->sw[2], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[1], sig->sw[3], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mod(B[1], aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  
  /* B[2] = A[0]^sw[4]*A[2]^sw[2]*(A[0]^2l_4*A[2]^2l_2)^(-c) */
  if(bigz_powm(aux, sig->A[0], sp_prod->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[2], grpkey->inner_gamma->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_invert(aux, aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux, aux, c, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[0], sig->sw[4], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[2], sig->sw[2], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mod(B[2], aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);

  /* B[3] = A[3]^sw[0]*A[11]^c*A[3]^(-c*2l_0) */
  if(bigz_invert(aux, sig->A[3], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux2, c, grpkey->inner_lambda->center) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux, aux, aux2, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[11], c, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[3], sig->sw[0], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mod(B[3], aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);

  /* B[4] = A[4]^sw[1]*A[12]^c*A[4]^(-c*2l_1)  */
  if(bigz_invert(aux, sig->A[4], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux2, c, grpkey->inner_lambda->center) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux, aux, aux2, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[12], c, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[4], sig->sw[1], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mod(B[4], aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);

  /* B[5] = A[5]^sw[4]*A[6]^sw[2]*A[7]^sw[0]*A[8]^sw[1]*(A[9]*A[5]^2l_4*A[6]^2l_2*A[7]^2l_0*A[8]^2l_1)^(-c) */
  if(bigz_powm(aux, sig->A[5], sp_prod->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[6], grpkey->inner_gamma->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[7], grpkey->inner_lambda->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[8], grpkey->inner_lambda->center, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, sig->A[9]) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_invert(aux, aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux, aux, c, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[5], sig->sw[4], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[6], sig->sw[2], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[7], sig->sw[0], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_powm(aux2, sig->A[8], sig->sw[1], grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mul(aux, aux, aux2) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);
  if(bigz_mod(B[5], aux, grpkey->n) == IERROR)
    GOTOENDRC(IERROR, _signature_recover_Bs);

  if(sphere_free(sp_prod)) rc = IERROR;
     
 _signature_recover_Bs_end:
     
  if(c) bigz_free(c);
  if(aux) bigz_free(aux);
  if(aux2) bigz_free(aux2);

  return rc;

}

int kty04_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, groupsig_key_t *grpkey) {
  
  kty04_grp_key_t *gkey;
  kty04_signature_t *kty04_sig;
  byte_t sc[SHA_DIGEST_LENGTH+1];
  SHA_CTX sha;
  bigz_t c, *B;
  char *aux_sB, *aux_sA;
  uint32_t i;
  int rc;
  uint8_t fail;

  if(!ok || !sig || !msg || 
     !grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  c = NULL; B = NULL;
  rc = IOK;

  gkey = (kty04_grp_key_t *) grpkey->key;
  kty04_sig = (kty04_signature_t *) sig->sig;

  /* 1) Check that each sw belongs to the adequate domain */
  if(_signature_check_sw_intervals(gkey, kty04_sig, &fail) == IERROR) {
    return IERROR;
  }

  if(fail) {
    *ok = 0;
    return IOK;
  }

  /* Initially, we set fail as true */
  fail = 1;

  /* 2) Recover the B's */
  if(!(B = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->z))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_verify", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  for(i=0; i<kty04_sig->z; i++) {
    if(!(B[i] = bigz_init())) GOTOENDRC(IERROR, kty04_verify);
  }

  if(_signature_recover_Bs(gkey, kty04_sig, B) == IERROR) GOTOENDRC(IERROR, kty04_verify);

  /* 3) Check that c = hash(message | B[0] | ... | B[z-1] | A[0] | ... | A[m-1]) */

  /* Initialize the hashing environment */
  /** @todo Use EVP_* instead of SHA1_* */
  if(!SHA1_Init(&sha)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_verify", __LINE__, EDQUOT,
		      "SHA1_Init", LOGERROR);
    GOTOENDRC(IERROR, kty04_verify);
  }

  /* Put the message into the hash */
  if(!SHA1_Update(&sha, msg->bytes, msg->length)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_verify", __LINE__, EDQUOT,
		      "SHA1_Update", LOGERROR);
    GOTOENDRC(IERROR, kty04_verify);    
  }

  for(i=0; i<kty04_sig->z; i++) {

    /* Put the i-th element of the array */
    if(!(aux_sB = bigz_get_str(10, B[i]))) GOTOENDRC(IERROR, kty04_verify);
    if(!SHA1_Update(&sha, aux_sB, strlen(aux_sB))) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_verify", __LINE__, EDQUOT,
			"SHA1_Update", LOGERROR);
      GOTOENDRC(IERROR, kty04_verify);    
    }

    free(aux_sB); aux_sB = NULL;
    bigz_free(B[i]);

  }

  free(B); B = NULL;

  for(i=0; i<kty04_sig->m; i++) {

    /* Put the i-th element of the array */
    if(!(aux_sA = bigz_get_str(10, kty04_sig->A[i]))) GOTOENDRC(IERROR, kty04_verify);
    if(!SHA1_Update(&sha, aux_sA, strlen(aux_sA))) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_verify", __LINE__, EDQUOT,
			"SHA1_Update", LOGERROR);
      GOTOENDRC(IERROR, kty04_verify);    
    }

    free(aux_sA); aux_sA = NULL;

  } 

  /* Calculate the hash */
  memset(sc, 0, SHA_DIGEST_LENGTH+1);
  if(!SHA1_Final(sc, &sha)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_verify", __LINE__, EDQUOT,
			"SHA1_Final", LOGERROR);
      GOTOENDRC(IERROR, kty04_verify);    
  }

  /* Now, we have to get c = h(message,B[1],...,B[z],A[1],...,A[m]) as an mpz */
  if(!(c = bigz_import(sc, SHA_DIGEST_LENGTH))) GOTOENDRC(IERROR, kty04_verify);

  /* Check the hash */
  errno = 0;
  if(bigz_cmp(c, kty04_sig->c)) {
    if(errno) GOTOENDRC(IERROR, kty04_verify);
    fail = 1;
    bigz_free(c);
    return IOK;
  } else {
    fail = 0;
  }

  /* 2) Check that each relation of the relation set is satisfied */
  /* return _kty04_signature_check_relations(gkey, sig, fail); */

  *ok = !fail;

 kty04_verify_end:
  
  bigz_free(c);
  return rc;

}

/* verify.c ends here */
