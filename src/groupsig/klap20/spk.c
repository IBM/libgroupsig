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

/**
 * DISCLAIMER: This file (and its header companion) will disappear once
 * issue23 is solved (https://github.com/IBM/libgroupsig/issues/23).
 */

#include "groupsig/klap20/spk.h"

spk_rep_t* spk_rep_init(uint16_t ns) {

  spk_rep_t *spk;

  if(!(spk = (spk_rep_t *) mem_malloc(sizeof(spk_rep_t)))) {
    return NULL;
  }

  if(!(spk->s = (pbcext_element_Fr_t **)
       mem_malloc(sizeof(pbcext_element_Fr_t *)*ns))) {
    return NULL;
  }

  spk->ns = ns;

  return spk;
  
}

int spk_rep_free(spk_rep_t *spk) {

  uint16_t i;
  
  if(!spk) {
    LOG_EINVAL_MSG(&logger, __FILE__, "spk_rep_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IERROR;
  }

  pbcext_element_Fr_free(spk->c);

  for(i=0; i<spk->ns; i++) {
    pbcext_element_Fr_free(spk->s[i]); spk->s[i] = NULL;
  }

  mem_free(spk->s); spk->s = NULL;
  mem_free(spk); spk = NULL;

  return IOK;
  
}

int klap20_spk0_sign(klap20_spk0_t *pi,
		     void *y[], uint16_t ny,
		     void *g[], uint16_t ng,
		     pbcext_element_Fr_t *x[], uint16_t nx,
		     uint16_t i[][2], uint16_t ni,
		     uint16_t *prods,
		     byte_t *msg, uint32_t size) {

  pbcext_element_Fr_t *r[3], *cx;
  void *prod[6], *gr[6];
  byte_t *by, *bg, *bprod, bi[4];
  hash_t *hc;
  uint64_t len;
  int rc;
  uint16_t j, k, l;
  
  if (!pi || !y || !g || !x || !i || !prods || !msg ||
      ny != 6 || ng != 5 || nx != 3 || ni != 8 || size <= 0) {
    LOG_EINVAL(&logger, __FILE__, "klap20_spk0_sign", __LINE__, LOGERROR);
    return IERROR;   
  }

  by = NULL; bg = NULL; bprod = NULL;
  hc = NULL;
  rc = IOK;
  
  /* All loops in this function can probably be unified and make all 
     more efficient... */
  for(j=0; j<nx; j++) {
    if (!(r[j] = pbcext_element_Fr_init())) GOTOENDRC(IERROR, klap20_spk0_sign);
    if (pbcext_element_Fr_random(r[j]) == IERROR)
      GOTOENDRC(IERROR, klap20_spk0_sign);
  }

  /* Compute the challenges according to the relations defined by 
     the i indexes */
  /* For now, we have no other choice but to manually compute the challenges.
     This will change with issue23 (https://github.com/IBM/libgroupsig/issues/23). */
  if (!(gr[0] = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G1_mul(gr[0], g[i[0][1]], r[i[0][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(gr[1] = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G1_mul(gr[1], g[i[1][1]], r[i[1][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(gr[2] = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_mul(gr[2], g[i[2][1]], r[i[2][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(gr[3] = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_mul(gr[3], g[i[3][1]], r[i[3][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(gr[4] = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_mul(gr[4], g[i[4][1]], r[i[4][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(gr[5] = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_mul(gr[5], g[i[5][1]], r[i[5][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(gr[6] = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_spk0_sign);  
  if (pbcext_element_G2_mul(gr[6], g[i[6][1]], r[i[6][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(gr[7] = pbcext_element_G2_init())) GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_mul(gr[7], g[i[7][1]], r[i[7][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);  
  
  /* Compute the challenge products. */
  /* Again, until issue23, manually. */
  if (pbcext_element_G1_set(prod[0], gr[0]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G1_set(prod[1], gr[1]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_set(prod[2], gr[2]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_set(prod[3], gr[3]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_set(prod[4], gr[4]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_add(prod[4], gr[5]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_set(prod[5], gr[6]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_add(prod[5], gr[7]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);  

  /* 
     Compute the hash:

     pi->c = Hash(msg, y[1..ny], g[1..ng], i[1,1], i[1,2] .. i[ni,1], i[ni,2], prod[1..ny]) 
     
     where prod[j] = g[i[j,2]]^r[i[j,1]]
  */

  /* Push the message */
  if(!(hc = hash_init(HASH_SHA1))) GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  
  /* Push the y values. Again, manually -- no loops */
  by = NULL;
  if(pbcext_element_G1_to_bytes(&by, &len, y[0]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(by); by = NULL;

  if(pbcext_element_G1_to_bytes(&by, &len, y[1]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[2]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[3]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[4]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[5]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(by); by = NULL;
  
  /* Push the base values -- again without loops */
  bg = NULL;
  if(pbcext_element_G1_to_bytes(&bg, &len, g[0]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bg); bg = NULL;
  
  if(pbcext_element_G1_to_bytes(&bg, &len, g[1]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[2]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[3]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[4]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bg); bg = NULL;  
  
  /* Push the indices */
  for(j=0; j<ni; j++) {
    memset(bi, 0, 4);
    bi[0] = i[j][0] & 0xFF;
    bi[1] = (i[j][0] & 0xFF00) >> 8;
    bi[2] = i[j][1] & 0xFF;
    bi[3] = (i[j][1] & 0xFF00) >> 8;
    if(hash_update(hc, bi, 4) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  }

  /* Push the products -- no loop */
  bprod = NULL;
  if(pbcext_element_G1_to_bytes(&bprod, &len, prod[0]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G1_to_bytes(&bprod, &len, prod[1]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[2]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[3]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[4]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[5]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);
  mem_free(bprod); bprod = NULL;  
  
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, klap20_spk0_sign);

  /* Convert the hash to an integer */
  if (!(pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_Fr_from_hash(pi->c, hc->hash, hc->length) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);

  /* Compute challenge responses */
  if (!(cx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_spk0_sign);

  for(j=0; j<pi->ns; j++) {
    
    /* si = ri - cxi */    
    if (pbcext_element_Fr_mul(cx, pi->c, x[j]) == IERROR)
      GOTOENDRC(IERROR, klap20_spk0_sign);
    if (!(pi->s[j] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klap20_spk0_sign);
    if (pbcext_element_Fr_sub(pi->s[j], r[j], cx) == IERROR)
      GOTOENDRC(IERROR, klap20_spk0_sign);
  
  }
  
 klap20_spk0_sign_end:

  pbcext_element_Fr_free(cx);
  
  for(j=0; j<nx; j++) {
    if (r[j]) { pbcext_element_Fr_free(r[j]); r[j] = NULL; }
  }
  
  if (prod[0]) { pbcext_element_G1_free(prod[0]); prod[0] = NULL; }
  if (prod[1]) { pbcext_element_G1_free(prod[1]); prod[1] = NULL; }
  if (prod[2]) { pbcext_element_G2_free(prod[2]); prod[2] = NULL; }
  if (prod[3]) { pbcext_element_G2_free(prod[3]); prod[3] = NULL; }
  if (prod[4]) { pbcext_element_G2_free(prod[4]); prod[4] = NULL; }
  if (prod[5]) { pbcext_element_G2_free(prod[5]); prod[5] = NULL; }

  if (gr[0]) { pbcext_element_G1_free(gr[0]); gr[0] = NULL; }
  if (gr[1]) { pbcext_element_G1_free(gr[1]); gr[1] = NULL; }
  if (gr[2]) { pbcext_element_G2_free(gr[2]); gr[2] = NULL; }
  if (gr[3]) { pbcext_element_G2_free(gr[3]); gr[3] = NULL; }
  if (gr[4]) { pbcext_element_G2_free(gr[4]); gr[4] = NULL; }
  if (gr[5]) { pbcext_element_G2_free(gr[5]); gr[5] = NULL; }

  if(by) { mem_free(by); by = NULL; }
  if(bg) { mem_free(bg); bg = NULL; }
  if(bprod) { mem_free(bprod); bprod = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
	  
  return rc;
	  
}

int klap20_spk0_verify(uint8_t *ok,
		       void *y[], uint16_t ny,
		       void *g[], uint16_t ng,
		       uint16_t i[][2], uint16_t ni,
		       uint16_t *prods,
		       klap20_spk0_t *pi,
		       byte_t *msg, uint32_t size) {
  
  pbcext_element_Fr_t *c;
  pbcext_element_G1_t *prod[6], *gs;
  byte_t *by, *bg, *bprod, bi[4];
  hash_t *hc;
  uint64_t len;
  int rc;
  uint16_t j, k, l;
	  
  if (!ok || !y || !g || !i || !prods || !pi || !msg ||
      ny != 6 || ng != 5 || ni <= 8 || size <= 0) {
    LOG_EINVAL(&logger, __FILE__, "spk_rep_verify", __LINE__, LOGERROR);
    return IERROR;   
  }

  by = NULL; bg = NULL; bprod = NULL;
  hc = NULL;
  rc = IOK;

  /* Compute the challenge products -- manually until fixing issue23 */
  if (!(gs = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[0] = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_mul(prod[0], y[0], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_mul(gs, g[i[0][1]], pi->s[i[0][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_add(prod[0], prod[0], gs) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[1] = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_mul(prod[1], y[1], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_mul(gs, g[i[1][1]], pi->s[i[1][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_add(prod[1], prod[1], gs) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[2] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(prod[2], y[2], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs, g[i[2][1]], pi->s[i[2][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[2], prod[2], gs) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[3] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(prod[3], y[3], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs, g[i[3][1]], pi->s[i[3][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[3], prod[3], gs) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[4] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(prod[4], y[4], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs, g[i[4][1]], pi->s[i[4][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[4], prod[4], gs) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs, g[i[5][1]], pi->s[i[5][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[4], prod[4], gs) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[5] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(prod[5], y[5], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs, g[i[6][1]], pi->s[i[6][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[5], prod[5], gs) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs, g[i[7][1]], pi->s[i[7][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[5], prod[5], gs) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);  
	  
  /* 
     if pi is correct, then pi->c must equal:

     Hash(msg, y[1..ny], g[1..ng], i[1,1], i[1,2] .. i[ni,1], i[ni,2], prod[1..ny]) 

     where prod[j] = y[j]^c*g[i[j,2]]^s[i[j,1]]
  */

  /* Push the message */
  if(!(hc = hash_init(HASH_SHA1))) GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);

  /* Push the y values -- manually */
  by = NULL;
  if(pbcext_element_G1_to_bytes(&by, &len, y[0]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G1_to_bytes(&by, &len, y[1]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[2]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[3]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[4]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[5]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(by); by = NULL;  

  /* Push the base values -- manually */
  bg = NULL;
  if(pbcext_element_G1_to_bytes(&bg, &len, g[0]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G1_to_bytes(&bg, &len, g[1]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[2]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[3]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[4]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bg); bg = NULL;   

  /* Push the indices */
  for(j=0; j<ni; j++) {
    memset(bi, 0, 4);
    bi[0] = i[j][0] & 0xFF;
    bi[1] = (i[j][0] & 0xFF00) >> 8;
    bi[2] = i[j][1] & 0xFF;
    bi[3] = (i[j][1] & 0xFF00) >> 8;
    if(hash_update(hc, bi, 4) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  }

  /* Push the products -- manually */
  bprod = NULL;
  if(pbcext_element_G1_to_bytes(&bprod, &len, prod[0]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G1_to_bytes(&bprod, &len, prod[1]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[2]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[3]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[4]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[5]) == IERROR)
    GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  mem_free(bprod); bprod = NULL;  
	  
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);

  /* Convert the hash to an integer */
  c = pbcext_element_Fr_init();
  pbcext_element_Fr_from_hash(c, hc->hash, hc->length);

  if(pbcext_element_Fr_cmp(c, pi->c)) {
    *ok = 0;
  } else {
    *ok = 1;
  }

 spk_rep_verify_end:

  if (c) { pbcext_element_Fr_free(c); c = NULL; }
  if (gs) { pbcext_element_G1_free(gs); gs = NULL; }

  if (prod[0]) { pbcext_element_G1_free(prod[0]); prod[0] = NULL; }
  if (prod[1]) { pbcext_element_G1_free(prod[1]); prod[1] = NULL; }
  if (prod[2]) { pbcext_element_G2_free(prod[2]); prod[2] = NULL; }
  if (prod[3]) { pbcext_element_G2_free(prod[3]); prod[3] = NULL; }
  if (prod[4]) { pbcext_element_G2_free(prod[4]); prod[4] = NULL; }
  if (prod[5]) { pbcext_element_G2_free(prod[5]); prod[5] = NULL; }  
  	    
  if(by) { mem_free(by); by = NULL; }
  if(bg) { mem_free(bg); bg = NULL; }
  if(bprod) { mem_free(bprod); bprod = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
	  
  return rc;
	  
}
