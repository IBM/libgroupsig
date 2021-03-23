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

#include "klap20.h"
#include "groupsig/klap20/grp_key.h"
#include "groupsig/klap20/mgr_key.h"
#include "groupsig/klap20/mem_key.h"
#include "groupsig/klap20/gml.h"
#include "groupsig/klap20/spk.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "shim/hash.h"
#include "sys/mem.h"

int klap20_get_joinseq(uint8_t *seq) {
  *seq = KLAP20_JOIN_SEQ;
  return IOK;
}

int klap20_get_joinstart(uint8_t *start) {
  *start = KLAP20_JOIN_START;
  return IOK;
}

/**
 * This process deviates slightly from what the KLAP20 paper defines, as the PKI
 * functionality is not integrated here. See the comment in the join_mem 
 * function for a detailed explanation.
 * 
 * In the join_mgr implemented here, we do not verify any signature of tau using
 * a "standard" keypair+certificate. Nor do we add the signature of tau to the
 * GML (because we don't receive such signature). Rather, it should be the caller
 * who takes care of that using some well tested library/software for PKI 
 * management.
 *
 * This can be easily done by a calling library as follows:
 *   1) The member digitally signs, using his PKI-backed identity, the bytearray
 *      representation of the <i>min</i> parameter when <i>seq</i>=2 (this
 *      contains the challenge response). 
 *   2) If the join is successful, the manager exports the newly created GML
 *      entry, producing a byte array (which contains the libgroupsig-internal
 *      identity -- an integer). 
 *   3) All the server running the issuer needs to store in its database, is
 *      the output of the previous steps. This can then be queried when an open
 *      is requested.
 */
int klap20_join_mgr(message_t **mout,
		  gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey) {

  klap20_mgr_key_t *klap20_mgrkey;
  klap20_grp_key_t *klap20_grpkey;
  gml_entry_t *klap20_entry;
  pbcext_element_G1_t *n, *f, *u, *v, *w;
  pbcext_element_G2_t *SS0, *SS1, *ff0, *ff1;
  pbcext_element_GT_t *tau;
  spk_rep_t *pi;
  hash_t *h;
  message_t *_mout;
  byte_t *bn, *bf, *bv;
  void *y[6], *g[5];  
  uint64_t len, nlen, flen, wlen, SS0len, SS1len, ff0len, ff1len, pilen, offset;
  uint8_t ok;
  int rc;
  uint16_t i[8][2], prods[6];  

  if((seq != 0 && seq != 2) ||
     !mout || !gml || gml->scheme != GROUPSIG_KLAP20_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_KLAP20_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_mgrkey = (klap20_mgr_key_t *) mgrkey->key;
  klap20_grpkey = (klap20_grp_key_t *) grpkey->key;
  klap20_entry = NULL;
  bn = bf = bv = NULL;
  n = f = u = v = w = NULL;
  SS0 = SS1 = ff0 = ff1 = NULL;
  tau = NULL;
  h = NULL;
  pi = NULL;
  rc = IOK;
  
  if (!seq) { /* First step */

    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_join_mgr);
    if(pbcext_element_G1_random(n) == IERROR) GOTOENDRC(IERROR, klap20_join_mgr);
    
    /* Dump the element into a message */
    if(pbcext_dump_element_G1_bytes(&bn, &len, n) == IERROR) 
      GOTOENDRC(IERROR, klap20_join_mgr);
    
    if(!*mout) {   
      if(!(_mout = message_from_bytes(bn, len))) {
	GOTOENDRC(IERROR, klap20_join_mgr);
      }

      *mout = _mout;
      
    } else {

      _mout = *mout;
      if(message_set_bytes(*mout, bn, len) == IERROR)
	GOTOENDRC(IERROR, klap20_join_mgr);
      
    }
    
  } else { /* Third step */

    /* Import the (n,f,w,SSO,SS1,ff0,ff1,pi) ad hoc message */

    if (!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_get_element_G1_bytes(n, &nlen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    offset = nlen;
    if (!(f = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_get_element_G1_bytes(f, &flen, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    offset += flen;
    if (!(w = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_get_element_G1_bytes(w, &wlen, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    offset += wlen;
    if (!(SS0 = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_get_element_G2_bytes(SS0, &SS0len, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    offset += SS0len;
    if (!(SS1 = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_get_element_G2_bytes(SS1, &SS1len, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    offset += SS1len;
    if (!(ff0 = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_get_element_G2_bytes(ff0, &ff0len, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    offset += ff0len;
    if (!(ff1 = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_get_element_G2_bytes(ff1, &ff1len, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    offset += ff1len;   
    if (!(pi = spk_rep_import(min->bytes + offset, &pilen)))
      GOTOENDRC(IERROR, klap20_join_mgr);
    offset += pilen;

    if (pbcext_element_G1_to_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);

    /* Check the SPK -- this will change with issue23 */
    /* Compute the SPK for sk -- this will be replaced in issue23 */

    /* u = Hash(f) */
    if(pbcext_dump_element_G1_bytes(&bf, &len, f) == IERROR) 
      GOTOENDRC(IERROR, klap20_join_mgr);    
    if(!(h = hash_init(HASH_BLAKE2)))
      GOTOENDRC(IERROR, klap20_join_mgr);
    if(hash_update(h, bf, len) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    if(hash_finalize(h) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    if(!(u = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klap20_join_mgr);
    if(pbcext_element_G1_from_hash(u, h->hash, h->length) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);    
        
    y[0] = f;
    y[1] = w;
    y[2] = SS0;
    y[3] = SS1;
    y[4] = ff0;
    y[5] = ff1;
  
    g[0] = klap20_grpkey->g;
    g[1] = u;
    g[2] = klap20_grpkey->gg;
    g[3] = klap20_grpkey->ZZ0;
    g[4] = klap20_grpkey->ZZ1;

    i[0][0] = 0; i[0][1] = 0; // alpha, g
    i[1][0] = 0; i[1][1] = 1; // alpha, u
    i[2][0] = 1; i[2][1] = 2; // s0, gg
    i[3][0] = 2; i[3][1] = 2; // s1, gg
    i[4][0] = 0; i[4][1] = 2; // alpha, gg
    i[5][0] = 1; i[5][1] = 3; // s0, ZZ0
    i[6][0] = 0; i[6][1] = 2; // alpha, gg
    i[7][0] = 2; i[7][1] = 4; // s1, ZZ1
  
    prods[0] = 1;
    prods[1] = 1;
    prods[2] = 1;
    prods[3] = 1;
    prods[4] = 2;
    prods[5] = 2;
    
    if (klap20_spk0_verify(&ok,
			   y, 6,
			   g, 5,
			   i, 8,
			   prods,
			   pi, bn, nlen) == IERROR) {
      GOTOENDRC(IERROR, klap20_join_mgr);
    }
    if (!ok) GOTOENDRC(IERROR, klap20_join_mgr);

    if (!(v = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_element_G1_mul(w, w, klap20_mgrkey->y) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_element_G1_mul(u, u, klap20_mgrkey->x) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_element_G1_add(v, u, w) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);    

    /* Add the tuple (i,SS0,SS1,ff0,ff1,tau) to the GML */
    if (!(tau = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, klap20_join_mgr);
    if (pbcext_pairing(tau, f, klap20_grpkey->gg) == IERROR)
      GOTOENDRC(IERROR, klap20_join_mgr);

    if(!(klap20_entry = klap20_gml_entry_init()))
      GOTOENDRC(IERROR, klap20_join_mgr);
    
    /* Currently, KLAP20 identities are just uint64_t's */
    klap20_entry->id = gml->n;
    if (!(klap20_entry->data = mem_malloc(sizeof(klap20_gml_entry_data_t))))
      GOTOENDRC(IERROR, klap20_join_mgr);
    ((klap20_gml_entry_data_t *) klap20_entry->data)->SS0 = SS0;
    ((klap20_gml_entry_data_t *) klap20_entry->data)->SS1 = SS1;
    ((klap20_gml_entry_data_t *) klap20_entry->data)->ff0 = ff0;
    ((klap20_gml_entry_data_t *) klap20_entry->data)->ff1 = ff1;    
    ((klap20_gml_entry_data_t *) klap20_entry->data)->tau = tau;

    if(gml_insert(gml, klap20_entry) == IERROR) GOTOENDRC(IERROR, klap20_join_mgr);

    /* Export v into a msg */
    bv = NULL;
    if(pbcext_dump_element_G1_bytes(&bv, &len, v) == IERROR) 
      GOTOENDRC(IERROR, klap20_join_mgr);

    if(!*mout) {
      
      if(!(_mout = message_from_bytes(bv, len)))
	GOTOENDRC(IERROR, klap20_join_mgr);
      *mout = _mout;

    } else {

      _mout = *mout;
      if(message_set_bytes(_mout, bv, len) == IERROR)
	GOTOENDRC(IERROR, klap20_join_mgr);

    }    
    
  }
  
 klap20_join_mgr_end:

  if (rc == IERROR) {
    if (SS0) { pbcext_element_G2_free(SS0); SS0 = NULL; }
    if (SS1) { pbcext_element_G2_free(SS1); SS1 = NULL; }
    if (ff0) { pbcext_element_G2_free(ff0); ff0 = NULL; }
    if (ff1) { pbcext_element_G2_free(ff1); ff1 = NULL; }    
    if (tau) { pbcext_element_GT_free(tau); tau = NULL; }  
    if (klap20_entry) { klap20_gml_entry_free(klap20_entry); klap20_entry = NULL; }
  }

  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (f) { pbcext_element_G1_free(f); f = NULL; }  
  if (u) { pbcext_element_G1_free(u); u = NULL; }
  if (v) { pbcext_element_G1_free(v); v = NULL; }
  if (w) { pbcext_element_G1_free(w); w = NULL; }
  if (h) { hash_free(h); h = NULL; }
  if (pi) { spk_rep_free(pi); pi = NULL; }
  if (bn) { mem_free(bn); bn = NULL; }
  if (bf) { mem_free(bf); bf = NULL; }  
  if (bv) { mem_free(bv); bv = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
