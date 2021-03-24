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
#include <errno.h>
#include <stdlib.h>

#include "gl19.h"
#include "logger.h"
#include "groupsig/gl19/identity.h"
#include "groupsig/gl19/grp_key.h"
#include "groupsig/gl19/mem_key.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "shim/hash.h"

int gl19_join_mem(message_t **mout, groupsig_key_t *memkey,
		  int seq, message_t *min, groupsig_key_t *grpkey) {

  pbcext_element_G1_t *n, *H, *aux;
  pbcext_element_Fr_t *y;
  pbcext_element_GT_t *e1, *e2, *e3;
  gl19_mem_key_t *gl19_memkey;
  groupsig_key_t *_gl19_memkey;
  gl19_grp_key_t *gl19_grpkey;
  message_t *_mout;  
  spk_dlog_t *pi;
  hash_t *hexpiration;
  byte_t *bn, *bmsg, *bH, *bpi, *bexpiration;
  uint64_t len, nlen, Hlen, pilen;
  int rc;

  if((seq != 1 && seq != 3) ||
     !min || (!mout && seq == 1) ||
     !memkey || memkey->scheme != GROUPSIG_GL19_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  pi = NULL; bn = NULL;
  n = NULL; H = NULL; aux = NULL;
  y = NULL;
  e1 = NULL; e2 = NULL; e3 = NULL;
  bmsg = NULL; bH = NULL; bpi = NULL; bexpiration = NULL;
  hexpiration = NULL;
  _gl19_memkey = NULL;
  pi = NULL;
  
  gl19_memkey = (gl19_mem_key_t *) memkey->key;
  gl19_grpkey = (gl19_grp_key_t *) grpkey->key;

  /* First step by the member: parse n and compute (Y,\pi_Y) */
  if (seq == 1) {
    if(!(n = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_join_mem);
    if(pbcext_get_element_G1_bytes(n, &len, min->bytes) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_element_G1_to_bytes(&bn, &len, n) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    /* Compute member's secret key y at random */
    if(!(gl19_memkey->y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_join_mem);
    if(pbcext_element_Fr_random(gl19_memkey->y) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    /* Compute the member's public key */
    if(!(gl19_memkey->H = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_element_G1_mul(gl19_memkey->H,
			     gl19_grpkey->h1, gl19_memkey->y) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    /* Compute the SPK */
    if(!(pi = spk_dlog_init())) GOTOENDRC(IERROR, gl19_join_mem);
    if(spk_dlog_G1_sign(pi, gl19_memkey->H,
			gl19_grpkey->h1, gl19_memkey->y, bn, len) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    /* Build the output message -- I don't like this */
    mem_free(bn); bn = NULL;
    if(pbcext_dump_element_G1_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);
    len = nlen;
    
    if(pbcext_dump_element_G1_bytes(&bH,
				    &Hlen,
				    gl19_memkey->H) == IERROR) 
      GOTOENDRC(IERROR, gl19_join_mem);
    len += Hlen;
   
    if(spk_dlog_export(&bpi, &pilen, pi) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);
    
    len += pilen;
    if(!(bmsg = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
      GOTOENDRC(IERROR, gl19_join_mem);

    memcpy(bmsg, bn, nlen);
    memcpy(&bmsg[nlen], bH, Hlen);
    memcpy(&bmsg[nlen+Hlen], bpi, pilen);
    
    if(!*mout) {
      if(!(_mout = message_from_bytes(bmsg, len)))
	GOTOENDRC(IERROR, gl19_join_mem);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR)
	GOTOENDRC(IERROR, gl19_join_mem);
    }
    
  } else {

    /* Second step by the member: Check correctness of computation 
       and update memkey */

    /* Min = (A,x,s,l) */
    _gl19_memkey = gl19_mem_key_import(min->bytes, min->length);
    if(!_gl19_memkey) GOTOENDRC(IERROR, gl19_join_mem);

    if(gl19_mem_key_copy(memkey, _gl19_memkey) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    /* Recompute h2s from s */
    if(!(gl19_memkey->h2s = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_join_mem);
    if(pbcext_element_G1_mul(gl19_memkey->h2s,
			     gl19_grpkey->h2,
			     gl19_memkey->s) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);   

    /* Recompute d and h3d from l */
    if (!(bexpiration = mem_malloc(sizeof(byte_t)*sizeof(uint64_t))))     
      GOTOENDRC(IERROR, gl19_join_mem);
    memcpy(bexpiration, &gl19_memkey->l, sizeof(uint64_t));
    if (!(hexpiration = hash_get(HASH_BLAKE2, bexpiration, sizeof(uint64_t))))
      GOTOENDRC(IERROR, gl19_join_mem);

    if (!(gl19_memkey->d = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_join_mem);
    if (pbcext_element_Fr_from_hash(gl19_memkey->d,
				    hexpiration->hash,
				    hexpiration->length) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(!(gl19_memkey->h3d = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_join_mem);
    if(pbcext_element_G1_mul(gl19_memkey->h3d,
			     gl19_grpkey->h3,
			     gl19_memkey->d) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    /* Check correctness */

    /* A must not be 1 (since we use additive notation for G1, 
       it must not be 0) */
    if(pbcext_element_G1_is0(gl19_memkey->A)) GOTOENDRC(IOK, gl19_join_mem);

    /* e(A,g2)e(A,ipk) = e(g1*Y*h2^s*h3^d,g2) */
    if(!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, gl19_join_mem);
    if(!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, gl19_join_mem);
    if(!(e3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, gl19_join_mem);
    if(!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_pairing(e1, gl19_memkey->A, gl19_grpkey->g2) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_element_GT_pow(e1, e1, gl19_memkey->x) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_pairing(e2, gl19_memkey->A, gl19_grpkey->ipk) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_element_GT_mul(e1, e1, e2) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_element_G1_set(aux, gl19_memkey->h2s) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_element_G1_add(aux, aux, gl19_memkey->h3d) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);    

    if(pbcext_element_G1_add(aux, aux, gl19_memkey->H) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_element_G1_add(aux, aux, gl19_grpkey->g1) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_pairing(e3, aux, gl19_grpkey->g2) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mem);

    if(pbcext_element_GT_cmp(e1, e3)) rc = IERROR;

  }

 gl19_join_mem_end:

  if(bn) { mem_free(bn); bn = NULL; }
  if(bH) { mem_free(bH); bH = NULL; }
  if(bpi) { mem_free(bpi); bpi = NULL; }
  if(bmsg) { mem_free(bmsg); bmsg = NULL; }
  if(n) { pbcext_element_G1_free(n); n = NULL; }
  if(H) { pbcext_element_G1_free(H); H = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(y) { pbcext_element_Fr_free(y); y = NULL; }
  if(e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if(e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if(e3) { pbcext_element_GT_free(e3); e3 = NULL; }
  if(_gl19_memkey) { gl19_mem_key_free(_gl19_memkey); _gl19_memkey = NULL; }
  if(pi) { spk_dlog_free(pi); pi = NULL; }
  if(hexpiration) { hash_free(hexpiration); hexpiration = NULL; }
  if(bexpiration) { mem_free(bexpiration); bexpiration = NULL; }

  return rc;

}

/* join.c ends here */
