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

#include "gl19.h"
#include "logger.h"
#include "bigz.h"
#include "groupsig/gl19/grp_key.h"
#include "groupsig/gl19/signature.h"
#include "sys/mem.h"
#include "shim/hash.h"

/* Private functions */
static int _gl19_verify_spk(uint8_t *ok,
			    gl19_signature_t *gl19_sig,
			    message_t *msg,
			    gl19_grp_key_t *gl19_grpkey) {

  pbcext_element_G1_t *A_d, *g1h3d, *y[6], *g[8];
  pbcext_element_Fr_t *expiration;
  hash_t *hexpiration;
  int rc;
  uint16_t i[11][2], prods[6]; 

  A_d = g1h3d = NULL;
  expiration = NULL;
  hexpiration = NULL;
  rc = IOK;
  
  /* No input checks, as the parameters have been checked by the caller. */
  
  /* Auxiliar variables for the spk */
  if(!(A_d = pbcext_element_G1_init())) return IERROR;
  if(pbcext_element_G1_sub(A_d, gl19_sig->A_, gl19_sig->d) == IERROR)
    GOTOENDRC(IERROR, _gl19_verify_spk);

  /* The last sizeof(uint64_t) bytes of the message contain the expiration
     date. Parse them, and recompute the h3d value, needed to verify the SPK. */
    if (!(hexpiration = hash_get(HASH_BLAKE2,
				 &msg->bytes[msg->length-sizeof(uint64_t)],
				 sizeof(uint64_t))))
      GOTOENDRC(IERROR, _gl19_verify_spk);

    if (!(expiration = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, _gl19_verify_spk);
    if (pbcext_element_Fr_from_hash(expiration,
				    hexpiration->hash,
				    hexpiration->length) == IERROR)
      GOTOENDRC(IERROR, _gl19_verify_spk);

    if(!(g1h3d = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, _gl19_verify_spk);
    if(pbcext_element_G1_mul(g1h3d,
			     gl19_grpkey->h3,
			     expiration) == IERROR)
      GOTOENDRC(IERROR, _gl19_verify_spk);
    if(pbcext_element_G1_add(g1h3d, g1h3d, gl19_grpkey->g1) == IERROR)
      GOTOENDRC(IERROR, _gl19_verify_spk);      

  /* Isn't there a more concise way to do the following? */
  y[0] = gl19_sig->nym1;
  y[1] = gl19_sig->nym2;
  y[2] = A_d;
  y[3] = g1h3d; //gl19_grpkey->g1;
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

  i[0][0] = 5; i[0][1] = 0;
  i[1][0] = 5; i[1][1] = 1;
  i[2][0] = 1; i[2][1] = 2;
  i[3][0] = 0; i[3][1] = 3;
  i[4][0] = 2; i[4][1] = 4;
  i[5][0] = 3; i[5][1] = 5;
  i[6][0] = 4; i[6][1] = 4;
  i[7][0] = 6; i[7][1] = 6;
  i[8][0] = 7; i[8][1] = 0;
  i[9][0] = 7; i[9][1] = 7;
  i[10][0] = 1; i[10][1] = 2;  

  prods[0] = 1;
  prods[1] = 2;
  prods[2] = 2;
  prods[3] = 3;
  prods[4] = 1;
  prods[5] = 2;
  
  /* Verify the SPK */
  if(spk_rep_verify(ok,
		    y, 6,
		    g, 8,
		    i, 11,
		    prods,
		    gl19_sig->pi,
		    msg->bytes, msg->length) == IERROR)
    rc = IERROR;
  
 _gl19_verify_spk_end:
  
  if (A_d) { pbcext_element_G1_free(A_d); A_d = NULL; }
  if (g1h3d) { pbcext_element_G1_free(g1h3d); g1h3d = NULL; }
  if (expiration) { pbcext_element_Fr_free(expiration); expiration = NULL; }  
  if (hexpiration) { hash_free(hexpiration); hexpiration = NULL; }
  
  return rc;

}

/* Public functions */
int gl19_verify(uint8_t *ok,
		groupsig_signature_t *sig,
		message_t *msg,
		groupsig_key_t *grpkey) {

  pbcext_element_GT_t *e1, *e2;
  gl19_signature_t *gl19_sig;
  gl19_grp_key_t *gl19_grpkey;
  message_t *msgexp;
  byte_t *bytesexp;
  time_t t;  
  int rc;
  
  if(!ok || !sig || !msg || 
     !grpkey || grpkey->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  e1 = NULL; e2 = NULL;

  gl19_sig = sig->sig;
  gl19_grpkey = grpkey->key;  

  /* The last sizeof(uint64_t) bytes of the message contain the expiration date
     of the credential used for signing -- which will be checked in the SPK. 
     Here, we just check that it is not less than the current time. */
  if (!(bytesexp = mem_malloc(sizeof(byte_t)*(msg->length+sizeof(uint64_t)))))
    GOTOENDRC(IERROR, gl19_verify);
  memcpy(bytesexp, msg->bytes, msg->length);
  memcpy(&bytesexp[msg->length], &gl19_sig->expiration, sizeof(uint64_t));
  if (!(msgexp = message_from_bytes(bytesexp, msg->length+sizeof(uint64_t))))
    GOTOENDRC(IERROR, gl19_verify);
  
  if ((t = time(NULL)) == (time_t) -1)
    GOTOENDRC(IERROR, gl19_verify);

  if (GL19_CRED_LIFETIME && t >= gl19_sig->expiration) 
    GOTOENDRC(IERROR, gl19_verify);
   
  /* AA must not be 1 (since we use additive notation for G1, 
     it must not be 0?) */
  if(pbcext_element_G1_is0(gl19_sig->AA)) {
    *ok = 0;
    GOTOENDRC(IOK, gl19_verify);
  }

  /* e(AA,ipk) must equal e(A_,g2) */
  if(!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, gl19_verify);
  if(pbcext_pairing(e1, gl19_sig->AA, gl19_grpkey->ipk) == IERROR)
    GOTOENDRC(IERROR, gl19_verify);
  if(!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, gl19_verify);
  if(pbcext_pairing(e2, gl19_sig->A_, gl19_grpkey->g2) == IERROR)
    GOTOENDRC(IERROR, gl19_verify);
  
  if(pbcext_element_GT_cmp(e1, e2)) {
    *ok = 0;
    GOTOENDRC(IOK, gl19_verify);
  }

  /* Verify the SPK */
  if(_gl19_verify_spk(ok, gl19_sig, msgexp, gl19_grpkey) == IERROR)
    GOTOENDRC(IERROR, gl19_verify);
  
 gl19_verify_end:

  if(e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if(e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if(bytesexp) { mem_free(bytesexp); bytesexp = NULL; }
  if(msgexp) { message_free(msgexp); msgexp = NULL; }
  
  return rc;

}

/* verify.c ends here */
