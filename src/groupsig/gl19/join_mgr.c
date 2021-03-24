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
#include "bigz.h"
#include "groupsig/gl19/grp_key.h"
#include "groupsig/gl19/mgr_key.h"
#include "groupsig/gl19/mem_key.h"
#include "groupsig/gl19/identity.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "shim/hash.h"
#include "crypto/spk.h"

int gl19_get_joinseq(uint8_t *seq) {
  *seq = GL19_JOIN_SEQ;
  return IOK;
}

int gl19_get_joinstart(uint8_t *start) {
  *start = GL19_JOIN_START;
  return IOK;
}

int gl19_join_mgr(message_t **mout, gml_t *gml, groupsig_key_t *mgrkey,
		  int seq, message_t *min, groupsig_key_t *grpkey) {

  pbcext_element_G1_t *n, *H, *h2s, *h3d;
  pbcext_element_Fr_t *aux, *d;
  gl19_grp_key_t *gl19_grpkey;
  gl19_mgr_key_t *gl19_mgrkey;
  gl19_mem_key_t *gl19_memkey;
  groupsig_key_t *memkey;
  message_t *_mout;
  spk_dlog_t *spk;
  hash_t *hexpiration;
  byte_t *bn, *bkey, *bexpiration;
  uint64_t len, _len;
  time_t expiration;
  uint32_t size;
  int rc, klen;
  uint8_t ok;

  if((seq != 0 && seq != 2) ||
     !mout || (!min && seq == 2) ||
     !mgrkey || mgrkey->scheme != GROUPSIG_GL19_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  bn = NULL; bkey = NULL; bexpiration = NULL;
  n = NULL; h2s = NULL; h3d = NULL; H = NULL;
  spk = NULL;
  aux = NULL; d = NULL;  
  memkey = NULL;
  hexpiration = NULL;
  
  gl19_grpkey = (gl19_grp_key_t *) grpkey->key;
  gl19_mgrkey = (gl19_mgr_key_t *) mgrkey->key;

  /* First step by manager: generate n */
  if (seq == 0) {
    
    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_G1_random(n) == IERROR) GOTOENDRC(IERROR, gl19_join_mgr);
    
    /* Dump the element into a message */
    if(pbcext_dump_element_G1_bytes(&bn, &len, n) == IERROR) 
      GOTOENDRC(IERROR, gl19_join_mgr);
    
    if(!*mout) {   
      if(!(_mout = message_from_bytes(bn, len))) {
	GOTOENDRC(IERROR, gl19_join_mgr);
      }

      *mout = _mout;
      
    } else {

      _mout = *mout;
      if(message_set_bytes(*mout, bn, len) == IERROR)
	GOTOENDRC(IERROR, gl19_join_mgr);
      
    }

  } else {

    /* Second step by manager: compute credential from H and pi_H */
    /* Verify the proof */

    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_get_element_G1_bytes(n, &len, min->bytes) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(!(H = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_get_element_G1_bytes(H, &_len, min->bytes + len) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(!(spk = spk_dlog_import(min->bytes + len + _len, &len)))
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_G1_to_bytes(&bn, &len, n) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(spk_dlog_G1_verify(&ok, H, gl19_grpkey->h1,
			  spk, bn, len) == IERROR) {
      GOTOENDRC(IERROR, gl19_join_mgr);
    }

    if(!ok) GOTOENDRC(IERROR, gl19_join_mgr);

    /* Pick x and s at random from Z*_p */
    if(!(memkey = gl19_mem_key_init())) GOTOENDRC(IERROR, gl19_join_mgr);
    gl19_memkey = memkey->key;

    if(!(gl19_memkey->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_Fr_random(gl19_memkey->x) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(!(gl19_memkey->s = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_Fr_random(gl19_memkey->s) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);

    /* Modification w.r.t. the GL19 paper: we add a maximum lifetime
       for member credentials. This is done by adding a second message
       to be signed in the BBS+ signatures. This message will then be
       "revealed" (i.e., shared in cleartext) in the SPK computed for
       signing. */

    /* d = hash(l) */
    expiration = time(NULL) + GL19_CRED_LIFETIME;
    if (expiration == (time_t) -1) GOTOENDRC(IERROR, gl19_join_mgr);
    gl19_memkey->l = (uint64_t) expiration;
    if (!(bexpiration = mem_malloc(sizeof(byte_t)*sizeof(uint64_t))))     
      GOTOENDRC(IERROR, gl19_join_mgr);
    memcpy(bexpiration, &gl19_memkey->l, sizeof(uint64_t));
    if (!(hexpiration = hash_get(HASH_BLAKE2, bexpiration, sizeof(uint64_t))))
      GOTOENDRC(IERROR, gl19_join_mgr);

    if (!(d = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_join_mgr);
    if (pbcext_element_Fr_from_hash(d,
				    hexpiration->hash,
				    hexpiration->length) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);

    /* Set A = (H*h_2^s*h3^d*g_1)^(1/isk+x) */
    if(!(gl19_memkey->A = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(!(h2s = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_G1_mul(h2s, gl19_grpkey->h2, gl19_memkey->s) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(!(h3d = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_G1_mul(h3d, gl19_grpkey->h3, d) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);    
    if(pbcext_element_G1_add(gl19_memkey->A, h2s, gl19_grpkey->g1) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_G1_add(gl19_memkey->A,
			     gl19_memkey->A,
			     h3d) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);    
    if(pbcext_element_G1_add(gl19_memkey->A, gl19_memkey->A, H) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(!(aux = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_Fr_add(aux, gl19_mgrkey->isk, gl19_memkey->x) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_Fr_inv(aux, aux) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);
    if(pbcext_element_G1_mul(gl19_memkey->A, gl19_memkey->A, aux) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);

    /* 
       Mout = (A,x,s,l) 
       This is stored in a partially filled memkey, byte encoded into a 
       message_t struct
    */

    bkey = NULL; 
    if (gl19_mem_key_export(&bkey, &size, memkey) == IERROR)
      GOTOENDRC(IERROR, gl19_join_mgr);

    if(!*mout) {
      if(!(_mout = message_from_bytes(bkey, size)))
	GOTOENDRC(IERROR, gl19_join_mgr);
      *mout = _mout;

    } else {

      _mout = *mout;
      if(message_set_bytes(_mout, bkey, size) == IERROR)
	GOTOENDRC(IERROR, gl19_join_mgr);
    }

  }
  
 gl19_join_mgr_end:

  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (H) { pbcext_element_G1_free(H); H = NULL; }  
  if (aux) { pbcext_element_Fr_free(aux); aux = NULL; }
  if (d) { pbcext_element_Fr_free(d); d = NULL; }  
  if (h2s) { pbcext_element_G1_free(h2s); h2s = NULL; }
  if (h3d) { pbcext_element_G1_free(h3d); h3d = NULL; }  
  if (memkey) { gl19_mem_key_free(memkey); memkey = NULL; }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  if (bn) { mem_free(bn); bn = NULL; }
  if (spk) { spk_dlog_free(spk); spk = NULL; }
  if (bexpiration) { mem_free(bexpiration); bexpiration = NULL; }
  if (hexpiration) { hash_free(hexpiration); hexpiration = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
