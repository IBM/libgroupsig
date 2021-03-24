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

#include "gl19.h"
#include "logger.h"
#include "sys/mem.h"
#include "groupsig/gl19/grp_key.h"
#include "groupsig/gl19/mem_key.h"
#include "groupsig/gl19/signature.h"

/* Private functions */

int gl19_sign(groupsig_signature_t *sig,
	      message_t *msg,
	      groupsig_key_t *memkey, 
	      groupsig_key_t *grpkey,
	      unsigned int seed) {

  /* Here we won't follow the typical C programming conventions for naming variables.
     Instead, we will name the variables as in the GL19 paper (with the exception 
     of doubling a letter when a ' is used, e.g. k' ==> kk and appending a '_' for
     variables named with a hat or something similar). Auxiliar variables 
     that are not specified in the paper but helpful or required for its 
     implementation will be named aux[_<name>]. */

  pbcext_element_Fr_t *alpha, *alpha2, *r1, *r2, *r3, *ss, *negy, *aux_Zr, *x[8];
  pbcext_element_G1_t *aux, *A_d, *g1h3d;
  pbcext_element_G1_t *y[6], *g[8];
  gl19_signature_t *gl19_sig;
  gl19_grp_key_t *gl19_grpkey;
  gl19_mem_key_t *gl19_memkey;
  message_t *msgexp;
  byte_t *bytesexp;
  uint64_t msgexp_len;
  uint16_t i[11][2], prods[6];
  int rc;

  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_GL19_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_sign", __LINE__, LOGERROR);
    return IERROR;
  }
  
  gl19_sig = sig->sig;
  gl19_grpkey = grpkey->key;
  gl19_memkey = memkey->key;
  rc = IOK;

  alpha = r1 = r2 = r3 = ss = negy = aux_Zr = NULL;
  aux = A_d = g1h3d = NULL;
  bytesexp = NULL;
  msgexp = NULL;

  /* alpha, r1, r2 \in_R Z_p */
  if(!(alpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_random(alpha) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(!(r1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_random(r1) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(!(r2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_random(r2) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* nym1 = g1^alpha */
  if(!(gl19_sig->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(gl19_sig->nym1, gl19_grpkey->g, alpha) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* nym2 = cpk^alpha*h^y */
  if(!(gl19_sig->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(!(aux = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(gl19_sig->nym2, gl19_grpkey->cpk, alpha) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(aux, gl19_grpkey->h, gl19_memkey->y) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_add(gl19_sig->nym2, gl19_sig->nym2, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* Add extra encryption of h^y with epk */
  if(!(alpha2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_random(alpha2) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  
  /* ehy1 = g1^alpha2 */
  if(!(gl19_sig->ehy1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(gl19_sig->ehy1, gl19_grpkey->g, alpha2) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);  

  /* ehy2 = epk^alpha2*h^y */
  if(!(gl19_sig->ehy2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(gl19_sig->ehy2, gl19_grpkey->epk, alpha2) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(aux, gl19_grpkey->h, gl19_memkey->y) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_add(gl19_sig->ehy2, gl19_sig->ehy2, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);  

  /* AA = A^r1*/
  if(!(gl19_sig->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(gl19_sig->AA, gl19_memkey->A, r1) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* A_ = AA^{-x}(g1*h1^y*h2^s*h3d)^r1 */
  /* Good thing we precomputed much of this... */
  if(!(gl19_sig->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(!(aux_Zr = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_add(aux, gl19_memkey->H, gl19_memkey->h2s) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_add(aux, gl19_grpkey->g1, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_add(aux, gl19_memkey->h3d, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);  
  if(pbcext_element_G1_mul(aux, aux, r1) == IERROR) // aux = (g1*h1^y*h2^s*h3^d)^r1
    GOTOENDRC(IERROR, gl19_sign); 
  if(pbcext_element_Fr_neg(aux_Zr, gl19_memkey->x) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(gl19_sig->A_, gl19_sig->AA, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_add(gl19_sig->A_, gl19_sig->A_, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* d = (g1*h1^y*h2^s*h3^d)^r1*h2^{-r2} */
  if(!(gl19_sig->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_neg(aux_Zr, r2) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_mul(gl19_sig->d, gl19_grpkey->h2, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_add(gl19_sig->d, aux, gl19_sig->d) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* r3 = r1^{-1} */
  if(!(r3 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_inv(r3, r1) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* ss = s - r2*r3 */
  if(!(ss = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_mul(aux_Zr, r2, r3) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_sub(ss, gl19_memkey->s, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* Auxiliar variables for the spk */
  if(pbcext_element_Fr_neg(aux_Zr, gl19_memkey->x) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_neg(ss, ss) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(!(negy = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_Fr_neg(negy, gl19_memkey->y) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);
  if(!(A_d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if(pbcext_element_G1_sub(A_d, gl19_sig->A_, gl19_sig->d) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* g1h3d = g1*h3^d */
  if (!(g1h3d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_sign);
  if (pbcext_element_G1_add(g1h3d, gl19_grpkey->g1, gl19_memkey->h3d) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

  /* Isn't there a more concise way to do the following? */
  y[0] = gl19_sig->nym1;
  y[1] = gl19_sig->nym2;
  y[2] = A_d;
  y[3] = g1h3d;
  y[4] = gl19_sig->ehy1;
  y[5] = gl19_sig->ehy2;
  
  g[0] = gl19_grpkey->g;
  g[1] = gl19_grpkey->cpk;
  g[2] = gl19_grpkey->h;
  g[3] = gl19_sig->AA;
  g[4] = gl19_grpkey->h2;
  g[5] = gl19_sig->d;
  g[6] = gl19_grpkey->h1;
  g[7] = gl19_grpkey->epk;

  x[0] = aux_Zr; // -x
  x[1] = gl19_memkey->y;
  x[2] = r2;
  x[3] = r3;
  x[4] = ss;
  x[5] = alpha;
  x[6] = negy;
  x[7] = alpha2;

  i[0][0] = 5; i[0][1] = 0; // alpha,g
  i[1][0] = 5; i[1][1] = 1; // alpha,cpk
  i[2][0] = 1; i[2][1] = 2; // y,h
  i[3][0] = 0; i[3][1] = 3; // -x,AA
  i[4][0] = 2; i[4][1] = 4; // r2,h2
  i[5][0] = 3; i[5][1] = 5; // r3,d
  i[6][0] = 4; i[6][1] = 4; // ss,h2
  i[7][0] = 6; i[7][1] = 6; // -y,h1
  i[8][0] = 7; i[8][1] = 0; // alpha2,g
  i[9][0] = 7; i[9][1] = 7; // alpha2,epk
  i[10][0] = 1; i[10][1] = 2; // y,h
  
  prods[0] = 1;
  prods[1] = 2;
  prods[2] = 2;
  prods[3] = 3;
  prods[4] = 1;
  prods[5] = 2;

  if(!(gl19_sig->pi = spk_rep_init(8))) GOTOENDRC(IERROR, gl19_sign);

  /* The SPK'ed message becomes the message to sign concatenated with the
     credential expiration date. */
  gl19_sig->expiration = gl19_memkey->l;
  msgexp_len = msg->length+sizeof(uint64_t);
  if (!(bytesexp = mem_malloc(sizeof(byte_t)*msgexp_len)))
    GOTOENDRC(IERROR, gl19_sign);
  memcpy(bytesexp, msg->bytes, msg->length);
  memcpy(&bytesexp[msg->length], &gl19_memkey->l, sizeof(uint64_t)); 
  if (!(msgexp = message_from_bytes(bytesexp, msgexp_len)))
    GOTOENDRC(IERROR, gl19_sign);

  if(spk_rep_sign(gl19_sig->pi,
		  y, 6, // element_t *y, uint16_t ny,
		  g, 8, // element_t *g, uint16_t ng,
		  x, 8, // element_t *x, uint16_t nx,
		  i, 11, // uint16_t **i, uint16_t ni,
		  prods,
		  msgexp->bytes, msgexp->length) == IERROR)
    GOTOENDRC(IERROR, gl19_sign);

 gl19_sign_end:

  if(alpha) { pbcext_element_Fr_free(alpha); alpha = NULL; }
  if(alpha2) { pbcext_element_Fr_free(alpha2); alpha2 = NULL; }
  if(r1) { pbcext_element_Fr_free(r1); r1 = NULL; }
  if(r2) { pbcext_element_Fr_free(r2); r2 = NULL; }
  if(r3) { pbcext_element_Fr_free(r3); r3 = NULL; }
  if(ss) { pbcext_element_Fr_free(ss); ss = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(aux_Zr) { pbcext_element_Fr_free(aux_Zr); aux_Zr = NULL; }
  if(negy) { pbcext_element_Fr_free(negy); negy = NULL; }
  if(A_d) { pbcext_element_G1_free(A_d); A_d = NULL; }
  if(g1h3d) { pbcext_element_G1_free(g1h3d); g1h3d = NULL; }
  if(msgexp) { message_free(msgexp); msgexp = NULL; }
  if(bytesexp) { mem_free(bytesexp); bytesexp = NULL; }

  if (rc == IERROR) {
    
    if(gl19_sig->nym1) {
      pbcext_element_G1_free(gl19_sig->nym1);
      gl19_sig->nym1 = NULL;
    }
    if(gl19_sig->nym2) {
      pbcext_element_G1_free(gl19_sig->nym2);
      gl19_sig->nym2 = NULL;
    }
    if(gl19_sig->AA) {
      pbcext_element_G1_free(gl19_sig->AA);
      gl19_sig->AA = NULL;
    }
    if(gl19_sig->A_) {
      pbcext_element_G1_free(gl19_sig->A_);
      gl19_sig->A_ = NULL;
    }
    if(gl19_sig->d) {
      pbcext_element_G1_free(gl19_sig->d);
      gl19_sig->d = NULL;
    }
    if(gl19_sig->pi) {
      spk_rep_free(gl19_sig->pi);
      gl19_sig->pi = NULL;
    }
    
  }
  
  return rc;
  
}

/* sign.c ends here */
