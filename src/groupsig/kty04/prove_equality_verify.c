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
#include "groupsig/kty04/sphere.h"
#include "groupsig/kty04/proof.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/signature.h"
#include "bigz.h"
#include "sys/mem.h"

/* Private functions */


/* Public functions */

int kty04_prove_equality_verify(uint8_t *ok, groupsig_proof_t *proof, 
				groupsig_key_t *grpkey, groupsig_signature_t **sigs, 
				uint16_t n_sigs) {
  
  kty04_grp_key_t *gkey;
  kty04_signature_t *sig;
  kty04_proof_t *kty04_proof;
  byte_t aux_sc[SHA_DIGEST_LENGTH+1];
  SHA_CTX aux_sha;
  bigz_t t7r, t7s, t6c, c;
  char *aux_t7r, *aux_t7, *aux_n;
  int rc;
  uint8_t i;
  
  if(!ok || !proof || proof->scheme != GROUPSIG_KTY04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE ||
     !sigs || !n_sigs) {
    LOG_EINVAL(&logger, __FILE__, "kty04_prove_equality_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  c = NULL; t7r = NULL; t7s = NULL; t6c = NULL;
  rc = IOK;
  
  gkey = (kty04_grp_key_t *) grpkey->key;
  kty04_proof = (kty04_proof_t *) proof->proof;

  /* Initialize the hashing environment */
  /** @todo Use EVP_* instead of SHA1_* */
  if(!SHA1_Init(&aux_sha)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality_verify", __LINE__, EDQUOT,
 		      "SHA1_Init", LOGERROR);
    GOTOENDRC(IERROR, kty04_prove_equality_verify);
  }
   
  /* We have to recover the T7^r objects. To do so, we divide T7^s/T6^c */  
  /* In a kty04_signature_t, T6 is stored in A[12] and T7 in A[4] */

  if(!(t7r = bigz_init()))
    GOTOENDRC(IERROR, kty04_prove_equality_verify);  

  if(!(t7s = bigz_init()))
    GOTOENDRC(IERROR, kty04_prove_equality_verify);

  if(!(t6c = bigz_init()))
    GOTOENDRC(IERROR, kty04_prove_equality_verify);
  
  for(i=0; i<n_sigs; i++) {

    sig = (kty04_signature_t *) sigs[i]->sig;
    if(sigs[i]->scheme != GROUPSIG_KTY04_CODE) {
      LOG_EINVAL(&logger, __FILE__, "kty04_prove_equality_verify", __LINE__, LOGERROR);
      GOTOENDRC(IERROR, kty04_prove_equality_verify);
    }
     
    if(bigz_powm(t7s, sig->A[4], kty04_proof->s, gkey->n) == IERROR)
      GOTOENDRC(IERROR, kty04_prove_equality_verify);

    if(bigz_powm(t6c, sig->A[12], kty04_proof->c, gkey->n) == IERROR)
      GOTOENDRC(IERROR, kty04_prove_equality_verify);

    if(bigz_mul(t7r, t7s, t6c) == IERROR)
      GOTOENDRC(IERROR, kty04_prove_equality_verify);

    if(bigz_mod(t7r, t7r, gkey->n) == IERROR)
      GOTOENDRC(IERROR, kty04_prove_equality_verify);
     
    /* Put the i-th element of the array */
    if(!(aux_t7r = bigz_get_str(10, t7r))) GOTOENDRC(IERROR, kty04_prove_equality_verify);
    if(!SHA1_Update(&aux_sha, aux_t7r, strlen(aux_t7r))) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality_verify", __LINE__, EDQUOT,
 			"SHA1_Update", LOGERROR);
      GOTOENDRC(IERROR, kty04_prove_equality_verify);
    }
    free(aux_t7r); aux_t7r = NULL;

    /* Put also the base (the T7's) into the hash */
    if(!(aux_t7 = bigz_get_str(10, sig->A[4]))) GOTOENDRC(IERROR, kty04_prove_equality_verify);
    if(!SHA1_Update(&aux_sha, aux_t7, strlen(aux_t7))) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality_verify", __LINE__, EDQUOT,
 			"SHA1_Update", LOGERROR);
      GOTOENDRC(IERROR, kty04_prove_equality_verify);
    }
    free(aux_t7); aux_t7 = NULL;
    
  }

  /* And finally, put the modulus into the hash */
  if(!(aux_n = bigz_get_str(10, gkey->n))) GOTOENDRC(IERROR, kty04_prove_equality_verify);
  if(!SHA1_Update(&aux_sha, aux_n, strlen(aux_n))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality_verify", __LINE__, EDQUOT,
 		      "SHA1_Update", LOGERROR);
    GOTOENDRC(IERROR, kty04_prove_equality_verify);
  }
  free(aux_n); aux_n = NULL;
    
  /* (2) Calculate c = hash(t7r[0] || t7[0] || ... || t7r[n-1] || t7[n-1] || mod ) */
  memset(aux_sc, 0, SHA_DIGEST_LENGTH+1);
  if(!SHA1_Final(aux_sc, &aux_sha)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "proof_equality_verify", __LINE__, EDQUOT,
 		      "SHA1_Final", LOGERROR);
    GOTOENDRC(IERROR, kty04_prove_equality_verify);
  }

  /* Now, we have to get c as a bigz_t */
  if(!(c = bigz_import(aux_sc, SHA_DIGEST_LENGTH)))
    GOTOENDRC(IERROR, kty04_prove_equality_verify);

  /* Compare the obtained c with the c received in the proof, if there is a 
     match, the proof is successful */
  errno = 0;
  if(!bigz_cmp(c, kty04_proof->c))
    *ok = 1;
  else
    *ok = 0;

  /* Free resources and exit */
 kty04_prove_equality_verify_end:
   
  if(c) bigz_free(c);
  if(t7r) bigz_free(t7r);
  if(t7s) bigz_free(t7s);
  if(t6c) bigz_free(t6c);
   
  return rc;
   
}

/* prove_equality_verify.c ends here */
