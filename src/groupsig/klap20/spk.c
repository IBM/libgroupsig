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

#include "crypto/spk.h"
#include "groupsig/klap20/spk.h"
#include "shim/hash.h"
#include "sys/mem.h"

int klap20_spk0_sign(spk_rep_t *pi,
		     void *y[], uint16_t ny,
		     void *g[], uint16_t ng,
		     pbcext_element_Fr_t *x[], uint16_t nx,
		     uint16_t i[][2], uint16_t ni,
		     uint16_t *prods,
		     byte_t *msg, uint32_t size) {

  pbcext_element_Fr_t *r[3], *cx;
  void *prod[6], *gr[8];
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
  cx = NULL;
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
  if (!(prod[0] = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G1_set(prod[0], gr[0]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(prod[1] = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_spk0_sign);  
  if (pbcext_element_G1_set(prod[1], gr[1]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(prod[2] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_sign);  
  if (pbcext_element_G2_set(prod[2], gr[2]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(prod[3] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_sign);  
  if (pbcext_element_G2_set(prod[3], gr[3]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(prod[4] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_sign);  
  if (pbcext_element_G2_set(prod[4], gr[4]) == IERROR)    
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_add(prod[4], gr[4], gr[5]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (!(prod[5] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_sign);    
  if (pbcext_element_G2_set(prod[5], gr[6]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);
  if (pbcext_element_G2_add(prod[5], gr[6], gr[7]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_sign);  

  /* 
     Compute the hash:

     pi->c = Hash(msg, y[1..ny], g[1..ng], i[1,1], i[1,2] .. i[ni,1], i[ni,2], prod[1..ny]) 
     
     where prod[j] = g[i[j,2]]^r[i[j,1]]
  */

  /* Push the message */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, klap20_spk0_sign);
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

  if (cx) { pbcext_element_Fr_free(cx); cx = NULL; }
  
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
  if (gr[6]) { pbcext_element_G2_free(gr[6]); gr[6] = NULL; }
  if (gr[7]) { pbcext_element_G2_free(gr[7]); gr[7] = NULL; }

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
		       spk_rep_t *pi,
		       byte_t *msg, uint32_t size) {
  
  pbcext_element_Fr_t *c;
  pbcext_element_G1_t *gs1;
  pbcext_element_G2_t *gs2;  
  void *prod[6];
  byte_t *by, *bg, *bprod, bi[4];
  hash_t *hc;
  uint64_t len;
  int rc;
  uint16_t j, k, l;
	  
  if (!ok || !y || !g || !i || !prods || !pi || !msg ||
      ny != 6 || ng != 5 || ni != 8 || size <= 0) {
    LOG_EINVAL(&logger, __FILE__, "klap20_spk0_verify", __LINE__, LOGERROR);
    return IERROR;   
  }

  by = NULL; bg = NULL; bprod = NULL;
  hc = NULL;
  rc = IOK;

  /* Compute the challenge products -- manually until fixing issue23 */
  if (!(gs1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (!(gs2 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);  

  if (!(prod[0] = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_mul(prod[0], y[0], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_mul(gs1, g[i[0][1]], pi->s[i[0][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_add(prod[0], prod[0], gs1) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[1] = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_mul(prod[1], y[1], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_mul(gs1, g[i[1][1]], pi->s[i[1][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G1_add(prod[1], prod[1], gs1) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[2] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(prod[2], y[2], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs2, g[i[2][1]], pi->s[i[2][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[2], prod[2], gs2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[3] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(prod[3], y[3], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs2, g[i[3][1]], pi->s[i[3][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[3], prod[3], gs2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[4] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(prod[4], y[4], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs2, g[i[4][1]], pi->s[i[4][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[4], prod[4], gs2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs2, g[i[5][1]], pi->s[i[5][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[4], prod[4], gs2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);

  if (!(prod[5] = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(prod[5], y[5], pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs2, g[i[6][1]], pi->s[i[6][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[5], prod[5], gs2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_mul(gs2, g[i[7][1]], pi->s[i[7][0]]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if (pbcext_element_G2_add(prod[5], prod[5], gs2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);  
	  
  /* 
     if pi is correct, then pi->c must equal:

     Hash(msg, y[1..ny], g[1..ng], i[1,1], i[1,2] .. i[ni,1], i[ni,2], prod[1..ny]) 

     where prod[j] = y[j]^c*g[i[j,2]]^s[i[j,1]]
  */

  /* Push the message */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);

  /* Push the y values -- manually */
  by = NULL;
  if(pbcext_element_G1_to_bytes(&by, &len, y[0]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G1_to_bytes(&by, &len, y[1]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[2]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[3]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[4]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(by); by = NULL;

  if(pbcext_element_G2_to_bytes(&by, &len, y[5]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(by); by = NULL;  

  /* Push the base values -- manually */
  bg = NULL;
  if(pbcext_element_G1_to_bytes(&bg, &len, g[0]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G1_to_bytes(&bg, &len, g[1]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[2]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[3]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bg); bg = NULL;

  if(pbcext_element_G2_to_bytes(&bg, &len, g[4]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bg); bg = NULL;   

  /* Push the indices */
  for(j=0; j<ni; j++) {
    memset(bi, 0, 4);
    bi[0] = i[j][0] & 0xFF;
    bi[1] = (i[j][0] & 0xFF00) >> 8;
    bi[2] = i[j][1] & 0xFF;
    bi[3] = (i[j][1] & 0xFF00) >> 8;
    if(hash_update(hc, bi, 4) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  }

  /* Push the products -- manually */
  bprod = NULL;
  if(pbcext_element_G1_to_bytes(&bprod, &len, prod[0]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G1_to_bytes(&bprod, &len, prod[1]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[2]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[3]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[4]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bprod); bprod = NULL;

  if(pbcext_element_G2_to_bytes(&bprod, &len, prod[5]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk0_verify);
  if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);
  mem_free(bprod); bprod = NULL;  
	  
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, klap20_spk0_verify);

  /* Convert the hash to an integer */
  c = pbcext_element_Fr_init();
  pbcext_element_Fr_from_hash(c, hc->hash, hc->length);

  if(pbcext_element_Fr_cmp(c, pi->c)) {
    *ok = 0;
  } else {
    *ok = 1;
  }

 klap20_spk0_verify_end:

  if (c) { pbcext_element_Fr_free(c); c = NULL; }
  if (gs1) { pbcext_element_G1_free(gs1); gs1 = NULL; }
  if (gs2) { pbcext_element_G2_free(gs2); gs2 = NULL; }

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

klap20_spk1_t* klap20_spk1_init() {

  klap20_spk1_t *pi;

  if (!(pi = mem_malloc(sizeof(klap20_spk1_t))))
    return NULL;

  pi->c = NULL;
  pi->s = NULL;
  pi->tau = NULL;

  return pi;

}

int klap20_spk1_free(klap20_spk1_t *pi) {

  int rc;
  
  if (!pi) return IOK;

  rc = IOK;

  if (pi->c) { rc = pbcext_element_Fr_free(pi->c); pi->c = NULL; }
  if (pi->s) { rc += pbcext_element_G2_free(pi->s); pi->s = NULL; }
  if (pi->tau) { rc += pbcext_element_GT_free(pi->tau); pi->tau = NULL; }  
  mem_free(pi);

  if (rc) rc = IERROR; 
  
  return rc;

}

int klap20_spk1_get_size(klap20_spk1_t *pi) {

  uint64_t size64, ss, sc, stau;
  
  if (!pi) {
    LOG_EINVAL(&logger, __FILE__, "klap20_spk1_sign", __LINE__, LOGERROR);    
    return -1;
  }

  ss = sc = 0;

  if (pbcext_element_Fr_byte_size(&sc) == -1) return -1;
  if (pbcext_element_G2_byte_size(&ss) == -1) return -1;
  if (pbcext_element_GT_byte_size(&stau) == -1) return -1;

  size64 = ss + sc + stau + sizeof(int)*3;
  if (size64 > INT_MAX) return -1;

  return (int) size64;
  
  
}

int klap20_spk1_export(byte_t **bytes,
		       uint64_t *len,
		       klap20_spk1_t *pi) {

  byte_t *bc, *bs, *btau, *_bytes;
  uint64_t clen, slen, taulen;
  int rc;
  
  if (!bytes || !len || !pi) {
    LOG_EINVAL(&logger, __FILE__, "klap20_spk1_export", __LINE__, LOGERROR);
    return IERROR;
  }

  bs = btau = bc = _bytes = NULL;  
  rc = IOK;

  if(pbcext_dump_element_Fr_bytes(&bc, &clen, pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_export);

  if(pbcext_dump_element_G2_bytes(&bs, &slen, pi->s) == IERROR) 
    GOTOENDRC(IERROR, klap20_spk1_export);

  if(pbcext_dump_element_GT_bytes(&btau, &taulen, pi->tau) == IERROR) 
    GOTOENDRC(IERROR, klap20_spk1_export);  

  if(!(_bytes = (byte_t *) mem_malloc(sizeof(byte_t)*(clen+slen+taulen))))
    GOTOENDRC(IERROR, klap20_spk1_export);
  
  memcpy(&_bytes, bc, clen);
  memcpy(&_bytes[clen], bs, slen);
  memcpy(&_bytes[clen+slen], btau, taulen);    
  
  if(!*bytes) *bytes = _bytes;
  else {
    memcpy(*bytes, _bytes, sizeof(byte_t)*(clen+slen+taulen));
    mem_free(_bytes); _bytes = NULL;
  }
  *len = clen + slen + taulen;

 klap20_spk1_export_end:

  if(bc) { mem_free(bc); bc = NULL; }  
  if(bs) { mem_free(bs); bs = NULL; }
  if(btau) { mem_free(btau); btau = NULL; }  

  return rc;

}

klap20_spk1_t* klap20_spk1_import(byte_t *bytes, uint64_t *len) {

  klap20_spk1_t *pi;
  uint64_t _len, offset;
  int rc;

  if(!bytes || !len) {
    LOG_EINVAL(&logger, __FILE__, "klap20_spk1_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(pi = klap20_spk1_init())) {
    return NULL;
  }

  rc = IOK;

  /* Get c */
  if(!(pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_spk1_import);
  if(pbcext_get_element_Fr_bytes(pi->c, &_len, bytes) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_import);
  offset = _len;  

  /* Get s */
  if(!(pi->s = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk1_import);
  if(pbcext_get_element_G2_bytes(pi->s, &_len, &bytes[offset]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_import);
  offset += _len;

  /* Get tau */
  if(!(pi->tau = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_spk1_import);
  if(pbcext_get_element_GT_bytes(pi->tau, &_len, &bytes[offset]) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_import);
  offset += _len;

  *len = offset;

 klap20_spk1_import_end:

  if(rc == IERROR && pi) { klap20_spk1_free(pi); pi = NULL; }
  
  return pi;  
  
}

int klap20_spk1_sign(klap20_spk1_t *pi,
		     pbcext_element_G2_t *xx,
		     pbcext_element_G1_t *g1,
		     pbcext_element_G1_t *g2,
		     pbcext_element_GT_t *e1,
		     pbcext_element_GT_t *e2,
		     byte_t *msg,
		     uint32_t size) {

  hash_t *h;
  pbcext_element_G2_t *rr;
  pbcext_element_GT_t *RR1, *RR2;
  byte_t *bytes;
  uint64_t len;  
  int rc;
  
  
  if (!pi || !xx || !g1 || !g2 || !e1 || !e2 || !msg || !size) {
    LOG_EINVAL(&logger, __FILE__, "klap20_spk1_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  rr = NULL;
  RR1 = RR2 = NULL;
  bytes = NULL;
  h = NULL;
  rc = IOK;

  /* RR1 = e(g1,rr), RR2 = e(g2,rr) */
  if (!(rr = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if (pbcext_element_G2_random(rr) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);

  if (!(RR1 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if (pbcext_pairing(RR1, g1, rr) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);

  if (!(RR2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if (pbcext_pairing(RR2, g2, rr) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);

  /* c = Hash(g1,g2,e1,e2,RR1,RR2,msg) */
  if (!(h = hash_init(HASH_BLAKE2)))
    GOTOENDRC(IERROR, klap20_spk1_sign);

  bytes = NULL;
  if (pbcext_element_G1_to_bytes(&bytes, &len, g1) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  mem_free(bytes); bytes = NULL;

  if (pbcext_element_G1_to_bytes(&bytes, &len, g2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);  
  mem_free(bytes); bytes = NULL;
  
  if (pbcext_element_GT_to_bytes(&bytes, &len, e1) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  mem_free(bytes); bytes = NULL;  

  if (pbcext_element_GT_to_bytes(&bytes, &len, e2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);  
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  mem_free(bytes); bytes = NULL;  

  if (pbcext_element_GT_to_bytes(&bytes, &len, RR1) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  mem_free(bytes); bytes = NULL;  

  if (pbcext_element_GT_to_bytes(&bytes, &len, RR2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  mem_free(bytes); bytes = NULL;  

  if(hash_update(h, msg, size) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  
  if(hash_finalize(h) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  
  /* Convert the hash to an integer */
  if (!(pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if (pbcext_element_Fr_from_hash(pi->c, h->hash, h->length) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);

  /* s = rr + xx^c */
  if (!(pi->s = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_spk1_sign);

  if (pbcext_element_G2_mul(pi->s, xx, pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);
  if (pbcext_element_G2_add(pi->s, rr, pi->s) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_sign);  

 klap20_spk1_sign_end:

  if (rr) { rc += pbcext_element_G2_free(rr); rr = NULL; }
  if (RR1) { rc += pbcext_element_GT_free(RR1); RR1 = NULL; }
  if (RR2) { rc += pbcext_element_GT_free(RR2); RR2 = NULL; }
  if (h) { rc += hash_free(h); h = NULL; }
  if (bytes) { rc += mem_free(bytes); bytes = NULL; }

  return rc;
  
}

int klap20_spk1_verify(uint8_t *ok,
		       klap20_spk1_t *pi,
		       pbcext_element_G1_t *g1,
		       pbcext_element_G1_t *g2,
		       pbcext_element_GT_t *e1,
		       pbcext_element_GT_t *e2,
		       byte_t *msg,
		       uint32_t size) {

  pbcext_element_Fr_t *c;
  pbcext_element_GT_t *RR1, *RR2, *aux;
  byte_t *bytes;
  hash_t *h;
  uint64_t len;
  int rc;

  if (!pi || !g1 || !g2 || !e1 || !e2 || !msg || !size) {
    LOG_EINVAL(&logger, __FILE__, "klap20_spk1_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  c = NULL;
  RR1 = RR2 = aux = NULL;
  bytes = NULL;
  rc = IOK;

  if (!(aux = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_spk1_verify);

  /* RR1 = e(g1,pi->s)/e1^pi->c */
  if (pbcext_element_GT_pow(aux, e1, pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);

  if (!(RR1 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if (pbcext_pairing(RR1, g1, pi->s) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if (pbcext_element_GT_div(RR1, RR1, aux) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);  

  /* RR2 = e(g2,pi->s)/e2^pi->c */
  if (pbcext_element_GT_pow(aux, e2, pi->c) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  
  if (!(RR2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if (pbcext_pairing(RR2, g2, pi->s) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if (pbcext_element_GT_div(RR2, RR2, aux) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);

  /* c = Hash(g1,g2,e1,e2,R1,R2,msg) */
  if (!(h = hash_init(HASH_BLAKE2)))
    GOTOENDRC(IERROR, klap20_spk1_verify);

  bytes = NULL;
  if (pbcext_element_G1_to_bytes(&bytes, &len, g1) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  mem_free(bytes); bytes = NULL;

  if (pbcext_element_G1_to_bytes(&bytes, &len, g2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);  
  mem_free(bytes); bytes = NULL;
  
  if (pbcext_element_GT_to_bytes(&bytes, &len, e1) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  mem_free(bytes); bytes = NULL;  

  if (pbcext_element_GT_to_bytes(&bytes, &len, e2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);  
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  mem_free(bytes); bytes = NULL;  

  if (pbcext_element_GT_to_bytes(&bytes, &len, RR1) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  mem_free(bytes); bytes = NULL;  

  if (pbcext_element_GT_to_bytes(&bytes, &len, RR2) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if(hash_update(h, bytes, len) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  mem_free(bytes); bytes = NULL;  

  if(hash_update(h, msg, size) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  
  if(hash_finalize(h) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);
  
  /* Convert the hash to an integer */
  if (!(c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_spk1_verify);
  if (pbcext_element_Fr_from_hash(c, h->hash, h->length) == IERROR)
    GOTOENDRC(IERROR, klap20_spk1_verify);

  if (pbcext_element_Fr_cmp(pi->c, c)) {
    *ok = 0;
  } else {
    *ok = 1;
  }

 klap20_spk1_verify_end:

  if (c) { rc += pbcext_element_Fr_free(c); c = NULL; }
  if (RR1) { rc += pbcext_element_GT_free(RR1); RR1 = NULL; }
  if (RR2) { rc += pbcext_element_GT_free(RR2); RR2 = NULL; }
  if (aux) { rc += pbcext_element_GT_free(aux); aux = NULL; }
  if (bytes) { rc += mem_free(bytes); bytes = NULL; }
  if (h) { rc += hash_free(h); h = NULL; }

  return rc ? IERROR : IOK;
  
}
