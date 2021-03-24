/*                               -*- Mode: C -*- 
 *
 *	libgroupsig Group Signatures library
 *	Copyright (C) 2012-2013 Jesus Diaz Vico
 *
 *		
 *
 *	This file is part of the libgroupsig Group Signatures library.
 *
 *
 *  The libgroupsig library is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  defined by the Free Software Foundation, either version 3 of the License, 
 *  or any later version.
 *
 *  The libroupsig library is distributed WITHOUT ANY WARRANTY; without even 
 *  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *  See the GNU Lesser General Public License for more details.
 *
 *
 *  You should have received a copy of the GNU Lesser General Public License 
 *  along with Group Signature Crypto Library.  If not, see <http://www.gnu.org/
 *  licenses/>
 *
 * @file: join.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: jue may 10 11:12:56 2012 (+0200)
 * @version: 
 * Last-Updated: lun ago  5 13:04:28 2013 (+0200)
 *           By: jesus
 *     Update #: 3
 * URL: 
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "dl21.h"
#include "groupsig/dl21/identity.h"
#include "groupsig/dl21/grp_key.h"
#include "groupsig/dl21/mem_key.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"

int dl21_join_mem(message_t **mout,
		  groupsig_key_t *memkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey) {

  pbcext_element_G1_t *n, *H, *aux;
  pbcext_element_Fr_t *y;
  pbcext_element_GT_t *e1, *e2, *e3;
  dl21_mem_key_t *dl21_memkey;
  groupsig_key_t *_dl21_memkey;
  dl21_grp_key_t *dl21_grpkey;
  message_t *_mout;
  spk_dlog_t *pi;
  byte_t *bn, *bmsg, *bH, *bpi;
  uint64_t len, nlen, Hlen, pilen;
  int rc;

  if((seq != 1 && seq != 3) ||
     !min || !mout ||
     !memkey || memkey->scheme != GROUPSIG_DL21_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  pi = NULL; bn = bmsg = bH = bpi = NULL;
  n = NULL; H = NULL; aux = NULL;
  y = NULL;
  e1 = NULL; e2 = NULL; e3 = NULL;
  _dl21_memkey = NULL;
  pi = NULL;
  
  dl21_memkey = (dl21_mem_key_t *) memkey->key;
  dl21_grpkey = (dl21_grp_key_t *) grpkey->key;

  /* First step by the member: parse n and compute (Y,\pi_Y) */
  if (seq == 1) {

    if(!(n = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_get_element_G1_bytes(n, &len, min->bytes) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);

    if(pbcext_element_G1_to_bytes(&bn, &len, n) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);

    /* Compute member's secret key y at random */
    if(!(dl21_memkey->y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_Fr_random(dl21_memkey->y) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);

    /* Compute the member's public key */
    if(!(dl21_memkey->H = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_G1_mul(dl21_memkey->H,
			     dl21_grpkey->h1, dl21_memkey->y) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);

    /* Compute the SPK */
    if(!(pi = spk_dlog_init())) GOTOENDRC(IERROR, dl21_join_mem);
    if(spk_dlog_G1_sign(pi, dl21_memkey->H,
			dl21_grpkey->h1, dl21_memkey->y, bn, len) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);

    /* Build the output message -- I don't like this */
    mem_free(bn); bn = NULL;
    if(pbcext_dump_element_G1_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    len = nlen;
    
    if(pbcext_dump_element_G1_bytes(&bH,
				    &Hlen,
				    dl21_memkey->H) == IERROR) 
      GOTOENDRC(IERROR, dl21_join_mem);
    len += Hlen;
   
    if(spk_dlog_export(&bpi, &pilen, pi) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    
    len += pilen;
    if(!(bmsg = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
      GOTOENDRC(IERROR, dl21_join_mem);

    memcpy(bmsg, bn, nlen);
    memcpy(&bmsg[nlen], bH, Hlen);
    memcpy(&bmsg[nlen+Hlen], bpi, pilen);
    
    if(!*mout) {
      if(!(_mout = message_from_bytes(bmsg, len)))
	GOTOENDRC(IERROR, dl21_join_mem);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR)
	GOTOENDRC(IERROR, dl21_join_mem);
    }
    
  } else {

    /* Second step by the member: Check correctness of computation 
       and update memkey */

    /* Min = (A,x,s) */
    _dl21_memkey = dl21_mem_key_import(min->bytes, min->length);
    if(!_dl21_memkey) GOTOENDRC(IERROR, dl21_join_mem);

    if(dl21_mem_key_copy(memkey, _dl21_memkey) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);

    /* Recompute h2s from s */
    if(!(dl21_memkey->h2s = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_G1_mul(dl21_memkey->h2s,
			     dl21_grpkey->h2,
			     dl21_memkey->s) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    
    /* Check correctness */

    /* A must not be 1 (since we use additive notation for G1, 
       it must not be 0) */
    if(pbcext_element_G1_is0(dl21_memkey->A)) GOTOENDRC(IOK, dl21_join_mem);

    /* e(A,g2)e(A,ipk) = e(g1Yh2^s,g2) */
    if(!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, dl21_join_mem);
    if(!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, dl21_join_mem);
    if(!(e3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, dl21_join_mem);
    if(!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21_join_mem);

    if(pbcext_pairing(e1, dl21_memkey->A, dl21_grpkey->g2) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_GT_pow(e1, e1, dl21_memkey->x) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_pairing(e2, dl21_memkey->A, dl21_grpkey->ipk) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_GT_mul(e1, e1, e2) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_G1_set(aux, dl21_memkey->h2s) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_G1_add(aux, aux, dl21_memkey->H) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_G1_add(aux, aux, dl21_grpkey->g1) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_pairing(e3, aux, dl21_grpkey->g2) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mem);
    if(pbcext_element_GT_cmp(e1, e3)) rc = IERROR;
    
  }

 dl21_join_mem_end:

  if(bn) { mem_free(bn); bn = NULL; }
  if(bmsg) { mem_free(bmsg); bmsg = NULL; }
  if(bpi) { mem_free(bpi); bpi = NULL; }
  if(bH) { mem_free(bH); bH = NULL; }
  if(n) { pbcext_element_G1_free(n); n = NULL; }  
  if(H) { pbcext_element_G1_free(H); H = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(y) { pbcext_element_Fr_free(y); y = NULL; }
  if(e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if(e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if(e3) { pbcext_element_GT_free(e3); e3 = NULL; }
  if(_dl21_memkey) {
    groupsig_mem_key_free(_dl21_memkey);
    _dl21_memkey = NULL;
  }
  if(pi) {
    spk_dlog_free(pi);
    pi = NULL;
  }
  
  return rc;

}

/* join.c ends here */
