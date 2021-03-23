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

#include "bbs04.h"
#include "groupsig/bbs04/grp_key.h"
#include "groupsig/bbs04/mem_key.h"
#include "groupsig/bbs04/signature.h"
#include "bigz.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

/* Private functions */

int bbs04_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey, unsigned int seed) {

  /* Here we won't follow the typical C programming conventions for naming variables.
     Instead, we will name the variables as in the BBS04 paper (with the exception 
     of doubling a letter when a ' is used, e.g. k' ==> kk). Auxiliar variables 
     that are not specified in the paper but helpful or required for its 
     implementation will be named aux_<name>. */

  pbcext_element_Fr_t *alpha, *beta, *delta1, *delta2, *ralpha, *rbeta, *rx;
  pbcext_element_Fr_t *rdelta1, *rdelta2, *alphabeta, *aux_Fr;
  pbcext_element_G1_t *R1, *R2, *R4, *R5, *aux_G1;
  pbcext_element_GT_t *R3, *aux_e1, *aux_e2, *aux_e3, *aux_o1;
  hash_t *aux_c;
  byte_t *aux_bytes;
  bbs04_signature_t *bbs04_sig;
  bbs04_grp_key_t *bbs04_grpkey;
  bbs04_mem_key_t *bbs04_memkey;
  uint64_t aux_n;
  int rc;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_BBS04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;

  bbs04_sig = sig->sig;
  bbs04_grpkey = grpkey->key;
  bbs04_memkey = memkey->key;

  alpha = beta = delta1 = delta2 = ralpha = rbeta = rx = NULL;
  rdelta1 = rdelta2 = alphabeta = aux_Fr = NULL;
  R1 = R2 = R4 = R5 = aux_G1 = NULL;
  R3 = aux_e1 = aux_e2 = aux_e3 = aux_o1 = NULL;

  /* alpha,beta \in_R Zp */
  if(!(alpha = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_random(alpha) == IERROR) GOTOENDRC(IERROR, bbs04_sign);
  if(!(beta = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_random(beta) == IERROR) GOTOENDRC(IERROR, bbs04_sign);

  /* Compute T1,T2,T3 */
  if(!(bbs04_sig->T1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_sign);
  if(!(bbs04_sig->T2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_sign);
  if(!(bbs04_sig->T3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_sign);

  /* T1 = u^alpha */
  if(pbcext_element_G1_mul(bbs04_sig->T1, bbs04_grpkey->u, alpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* T2 = v^beta */
  if(pbcext_element_G1_mul(bbs04_sig->T2, bbs04_grpkey->v, beta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* T3 = A*h^(alpha+beta) */
  if(!(alphabeta = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_add(alphabeta, alpha, beta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_mul(bbs04_sig->T3, bbs04_grpkey->h, alphabeta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_add(bbs04_sig->T3, bbs04_memkey->A, bbs04_sig->T3) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* delta1 = x*alpha */
  if(!(delta1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_mul(delta1, bbs04_memkey->x, alpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* delta2 = x*beta */
  if(!(delta2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_mul(delta2, bbs04_memkey->x, beta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  /* ralpha, rbeta, rx, rdelta1, rdelta2 \in_R Zp */
  if(!(ralpha = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_random(ralpha) == IERROR) GOTOENDRC(IERROR, bbs04_sign);
  if(!(rbeta = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_random(rbeta) == IERROR) GOTOENDRC(IERROR, bbs04_sign);
  if(!(rx = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_random(rx) == IERROR) GOTOENDRC(IERROR, bbs04_sign);
  if(!(rdelta1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_random(rdelta1) == IERROR) GOTOENDRC(IERROR, bbs04_sign);
  if(!(rdelta2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_random(rdelta2) == IERROR) GOTOENDRC(IERROR, bbs04_sign);

  /* Compute R1, R2, R3, R4, R5 */
  /* Optimized o1 = e(T3, g2) = e(A, g2) * e(h, g2) ^ alpha + beta */
  if(!(aux_o1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_GT_pow(aux_o1, bbs04_grpkey->hg2, alphabeta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_GT_mul(aux_o1, aux_o1, bbs04_memkey->Ag2) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* R1 = u^ralpha */
  if(!(R1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_mul(R1, bbs04_grpkey->u, ralpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* R2 = v^rbeta */
  if(!(R2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_mul(R2, bbs04_grpkey->v, rbeta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* R3 = e(T3,g2)^rx * e(h,w)^(-ralpha-rbeta) * e(h,g2)^(-rdelta1-rdelta2) */
  if(!(aux_e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(!(aux_e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(!(aux_e3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_sign);
  
  /* e1 = e(T3,g2)^rx */
  //element_pairing(aux_e1, bbs04_sig->T3, bbs04_grpkey->g2);
  if(pbcext_element_GT_pow(aux_e1, aux_o1, rx) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  /* e2 = e(h,w)^(-ralpha-rbeta) */
  //element_pairing(aux_e2, bbs04_grpkey->h, bbs04_grpkey->w);
  if(!(aux_Fr = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_neg(aux_Fr, ralpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_sub(aux_Fr, aux_Fr, rbeta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_GT_pow(aux_e2, bbs04_grpkey->hw, aux_Fr) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* e3 = e(h,g2)^(-rdelta1-rdelta2) */
  //element_pairing(aux_e3, bbs04_grpkey->h, bbs04_grpkey->g2);
  if(pbcext_element_Fr_neg(aux_Fr, rdelta1) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_sub(aux_Fr, aux_Fr, rdelta2) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_GT_pow(aux_e3, bbs04_grpkey->hg2, aux_Fr) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
    
  /* R3 = e1 * e2 * e3 */
  if(!(R3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_GT_mul(R3, aux_e1, aux_e2) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_GT_mul(R3, R3, aux_e3) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* R4 = T1^rx * u^-rdelta1 */
  if(!(R4 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_mul(R4, bbs04_sig->T1, rx) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(!(aux_G1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_neg(aux_Fr, rdelta1) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_mul(aux_G1, bbs04_grpkey->u, aux_Fr) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_add(R4, R4, aux_G1) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* R5 = T2^rx * v^-rdelta2 */
  if(!(R5 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_mul(R5, bbs04_sig->T2, rx) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_neg(aux_Fr, rdelta2) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_mul(aux_G1, bbs04_grpkey->v, aux_Fr) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_G1_add(R5, R5, aux_G1) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* c = hash(M,T1,T2,T3,R1,R2,R3,R4,R5) \in Zp */
  if(!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, bbs04_sign);

  /* Push the message */
  if(hash_update(aux_c, msg->bytes, msg->length) == IERROR) 
    GOTOENDRC(IERROR, bbs04_sign);

  /* Push T1 */
  aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, bbs04_sig->T1) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push T2 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, bbs04_sig->T2) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push T3 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, bbs04_sig->T3) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R1 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, R1) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R2 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, R2) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R3 */
  if(pbcext_element_GT_to_bytes(&aux_bytes, &aux_n, R3) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R4 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, R4) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R5 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, R5) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  mem_free(aux_bytes); aux_bytes = NULL;  

  /* Finish the hash */
  if(hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, bbs04_sign);

  /* Get c as the element associated to the obtained hash value */
  if(!(bbs04_sig->c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_from_hash(bbs04_sig->c, aux_c->hash, aux_c->length) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* Calculate salpha, sbeta, sx, sdelta1, sdelta2 */

  /* salpha = ralpha + c*alpha */
  if(!(bbs04_sig->salpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_mul(bbs04_sig->salpha, bbs04_sig->c, alpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_add(bbs04_sig->salpha, bbs04_sig->salpha, ralpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* sbeta = rbeta + c*beta */
  if(!(bbs04_sig->sbeta = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_mul(bbs04_sig->sbeta, bbs04_sig->c, beta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_add(bbs04_sig->sbeta, bbs04_sig->sbeta, rbeta) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* sx = rx + c*x */
  if(!(bbs04_sig->sx = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_mul(bbs04_sig->sx, bbs04_sig->c, bbs04_memkey->x) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_add(bbs04_sig->sx, bbs04_sig->sx, rx) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* sdelta1 = rdelta1 + c*delta1 */
  if(!(bbs04_sig->sdelta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_mul(bbs04_sig->sdelta1, bbs04_sig->c, delta1) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_add(bbs04_sig->sdelta1, bbs04_sig->sdelta1, rdelta1) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

  /* sdelta2 = rdelta2 + c*delta2 */
  if(!(bbs04_sig->sdelta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_mul(bbs04_sig->sdelta2, bbs04_sig->c, delta2) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);
  if(pbcext_element_Fr_add(bbs04_sig->sdelta2, bbs04_sig->sdelta2, rdelta2) == IERROR)
    GOTOENDRC(IERROR, bbs04_sign);

 bbs04_sign_end:

  /* pbcext_element_G1_t *aux_G1; */
  /* pbcext_element_GT_t  *aux_e1, *aux_e2, *aux_e3, *aux_o1; */
  
  if(R1) { pbcext_element_G1_free(R1); R1 = NULL; }
  if(R2) { pbcext_element_G1_free(R2); R2 = NULL; }
  if(R3) { pbcext_element_GT_free(R3); R3 = NULL; }
  if(R4) { pbcext_element_G1_free(R4); R4 = NULL; }
  if(R5) { pbcext_element_G1_free(R5); R5 = NULL; } 
  if(alpha) { pbcext_element_Fr_free(alpha); alpha = NULL; }
  if(beta) { pbcext_element_Fr_free(beta); beta = NULL; }
  if(delta1) { pbcext_element_Fr_free(delta1); delta1 = NULL; }
  if(delta2) { pbcext_element_Fr_free(delta2); delta2 = NULL; }
  if(ralpha) { pbcext_element_Fr_free(ralpha); ralpha = NULL; }
  if(rbeta) { pbcext_element_Fr_free(rbeta); rbeta = NULL; }
  if(rx) { pbcext_element_Fr_free(rx); rx = NULL; }
  if(rdelta1) { pbcext_element_Fr_free(rdelta1); rdelta1 = NULL; }
  if(rdelta2) { pbcext_element_Fr_free(rdelta2); rdelta2 = NULL; }
  if(alphabeta) { pbcext_element_Fr_free(alphabeta); alphabeta = NULL; }
  if(aux_Fr) { pbcext_element_Fr_free(aux_Fr); aux_Fr = NULL; }
  if(R4) { pbcext_element_G1_free(R4); R4 = NULL; }
  if(aux_G1) { pbcext_element_G1_free(aux_G1); aux_G1 = NULL; }
  if(aux_e1) { pbcext_element_GT_free(aux_e1); aux_e1 = NULL; }
  if(aux_e2) { pbcext_element_GT_free(aux_e2); aux_e2 = NULL; }
  if(aux_e3) { pbcext_element_GT_free(aux_e3); aux_e3 = NULL; }
  if(aux_o1) { pbcext_element_GT_free(aux_o1); aux_o1 = NULL; }

  if(aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }
  if(aux_c) { hash_free(aux_c); aux_c = NULL; }

  return rc;
  
}

/* sign.c ends here */
