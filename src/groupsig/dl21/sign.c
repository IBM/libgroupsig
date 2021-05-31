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

#include "dl21.h"
#include "groupsig/dl21/grp_key.h"
#include "groupsig/dl21/mem_key.h"
#include "groupsig/dl21/signature.h"
#include "shim/hash.h"
#include "sys/mem.h"

int dl21_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	      groupsig_key_t *grpkey, unsigned int seed) {

  /* Here we won't follow the typical C programming conventions for naming variables.
     Instead, we will name the variables as in the DL21 paper (with the exception 
     of doubling a letter when a ' is used, e.g. k' ==> kk and appending a '_' for
     variables named with a hat or something similar). Auxiliar variables 
     that are not specified in the paper but helpful or required for its 
     implementation will be named aux[_<name>]. */

  pbcext_element_Fr_t *r1, *r2, *r3, *ss, *negy, *aux_Zr, *x[7];
  pbcext_element_G1_t *aux, *aux_h2negr2, *A_d, *hscp;
  pbcext_element_G1_t *y[3], *g[5];
  dl21_signature_t *dl21_sig;
  dl21_grp_key_t *dl21_grpkey;
  dl21_mem_key_t *dl21_memkey;
  /* dl21_sysenv_t *dl21_sysenv; */
  hash_t *hc;
  char *msg_msg, *msg_scp;
  uint16_t i[6][2], prods[3];
  int rc;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_DL21_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21_sig = sig->sig;
  dl21_grpkey = grpkey->key;
  dl21_memkey = memkey->key;
  /* dl21_sysenv = sysenv->data; */
  rc = IOK;

  r1 = r2 = r3 = ss = negy = aux_Zr = NULL;
  aux = aux_h2negr2 = A_d = NULL;
  msg_msg = NULL; msg_scp = NULL;
  hc = NULL;
  
  /* Parse message and scope values from msg */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  
  /* r1, r2 \in_R Z_p */
  if(!(r1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_Fr_random(r1) == IERROR) GOTOENDRC(IERROR, dl21_sign);
  if(!(r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_Fr_random(r2) == IERROR) GOTOENDRC(IERROR, dl21_sign);

  /* nym = Hash(scp)^y */
  dl21_sig->nym = pbcext_element_G1_init();
  hscp = pbcext_element_G1_init();
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, dl21_sign);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, dl21_sign);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  if(pbcext_element_G1_mul(dl21_sig->nym, hscp, dl21_memkey->y) == IERROR)
    GOTOENDRC(IERROR, dl21_sign); 

  /* AA = A^r1*/
  if(!(dl21_sig->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_mul(dl21_sig->AA, dl21_memkey->A, r1) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);

  /* A_ = AA^{-x}(g1*h1^y*h2^s)^r1 */
  /* Good thing we precomputed much of this... */
  if(!(aux = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(!(dl21_sig->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(!(aux_Zr = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_add(aux, dl21_memkey->H, dl21_memkey->h2s) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_add(aux, dl21_grpkey->g1, aux) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_mul(aux, aux, r1) == IERROR) // aux = (g1*h1^y*h2^s)^r1
    GOTOENDRC(IERROR, dl21_sign); 
  if(pbcext_element_Fr_neg(aux_Zr, dl21_memkey->x) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_mul(dl21_sig->A_, dl21_sig->AA, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_add(dl21_sig->A_, dl21_sig->A_, aux) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  /* d = (g1*h1^y*h2^s)^r1*h2^{-r2} */
  if(!(dl21_sig->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(!(aux_h2negr2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_Fr_neg(aux_Zr, r2) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_mul(dl21_sig->d, dl21_grpkey->h2, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_add(dl21_sig->d, aux, dl21_sig->d) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);

  /* r3 = r1^{-1} */
  if(!(r3 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_Fr_inv(r3, r1) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);

  /* ss = s - r2*r3 */
  if(!(ss = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_Fr_mul(aux_Zr, r2, r3) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_Fr_sub(ss, dl21_memkey->s, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);

  /* Auxiliar variables for the spk */
  if(pbcext_element_Fr_neg(aux_Zr, dl21_memkey->x) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_Fr_neg(ss, ss) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(!(negy = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_Fr_neg(negy, dl21_memkey->y) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);
  if(!(A_d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_sign);
  if(pbcext_element_G1_sub(A_d, dl21_sig->A_, dl21_sig->d) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);

  // @TODO Check
  /* Isn't there a more concise way to do the following? */
  y[0] = dl21_sig->nym;
  y[1] = A_d;
  y[2] = dl21_grpkey->g1;

  g[0] = hscp;
  g[1] = dl21_sig->AA;
  g[2] = dl21_grpkey->h2;
  g[3] = dl21_sig->d;
  g[4] = dl21_grpkey->h1;

  x[0] = aux_Zr; // -x
  x[1] = dl21_memkey->y;
  x[2] = r2;
  x[3] = r3;
  x[4] = ss; // -ss
  x[5] = negy;

  i[0][0] = 1; i[0][1] = 0; // hscp^y = (g[0],x[1])
  i[1][0] = 0; i[1][1] = 1; // AA^-x = (g[1],x[0])
  i[2][0] = 2; i[2][1] = 2; // h2^r2 = (g[2],x[2])
  i[3][0] = 3; i[3][1] = 3; // d^r3 = (g[3],x[3])
  i[4][0] = 4; i[4][1] = 2; // h2^-ss = (g[2],x[4])
  i[5][0] = 5; i[5][1] = 4; // h1^-y = (g[4],x[5])

  prods[0] = 1;
  prods[1] = 2;
  prods[2] = 3;
  
  if(!(dl21_sig->pi = spk_rep_init(6))) GOTOENDRC(IERROR, dl21_sign);
  if(spk_rep_sign(dl21_sig->pi,
		  y, 3, // element_t *y, uint16_t ny,
		  g, 5, // element_t *g, uint16_t ng,
		  x, 6, // element_t *x, uint16_t nx,
		  i, 6, // uint16_t **i, uint16_t ni,
		  prods,
		  (byte_t *) msg_msg, strlen(msg_msg)) == IERROR)
    GOTOENDRC(IERROR, dl21_sign);

 dl21_sign_end:

  if(r1) { pbcext_element_Fr_free(r1); r1 = NULL; }
  if(r2) { pbcext_element_Fr_free(r2); r2 = NULL; }
  if(r3) { pbcext_element_Fr_free(r3); r3 = NULL; }
  if(ss) { pbcext_element_Fr_free(ss); ss = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(aux_Zr) { pbcext_element_Fr_free(aux_Zr); aux = NULL; }
  if(aux_h2negr2) { pbcext_element_G1_free(aux_h2negr2); aux_h2negr2 = NULL; }
  if(negy) { pbcext_element_Fr_free(negy); negy = NULL; }
  if(A_d) { pbcext_element_G1_free(A_d); A_d = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  
  if (rc == IERROR) {
    
    if(dl21_sig->nym) {
      pbcext_element_G1_free(dl21_sig->nym);
      dl21_sig->nym = NULL;
    }
    if(dl21_sig->AA) {
      pbcext_element_G1_free(dl21_sig->AA);
      dl21_sig->AA = NULL;
    }
    if(dl21_sig->A_) {
      pbcext_element_G1_free(dl21_sig->A_);
      dl21_sig->A_ = NULL;
    }
    if(dl21_sig->d) {
      pbcext_element_G1_free(dl21_sig->d);
      dl21_sig->d = NULL;
    }
    if(dl21_sig->pi) {
      spk_rep_free(dl21_sig->pi);
      dl21_sig->pi = NULL;
    }
    
  }
  
  return rc;
  
}

/* sign.c ends here */
