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

#include "spk.h"

#include "sys/mem.h"
#include "shim/hash.h"

spk_dlog_t* spk_dlog_init() {

  spk_dlog_t *spk;

  if(!(spk = (spk_dlog_t *) mem_malloc(sizeof(spk_dlog_t)))) {
    return NULL;
  }

  return spk;
  
}

int spk_dlog_free(spk_dlog_t *spk) {

  if(!spk) {
    LOG_EINVAL_MSG(&logger, __FILE__, "spk_dlog_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IERROR;
  }

  pbcext_element_Fr_free(spk->c); spk->c = NULL;
  pbcext_element_Fr_free(spk->s); spk->s = NULL;
  mem_free(spk); spk = NULL;

  return IOK;
  
}

int spk_dlog_copy(spk_dlog_t *dst, spk_dlog_t *src) {

  int rc;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;

  if (!(dst->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_dlog_copy);
  if (pbcext_element_Fr_set(dst->c, src->c) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_copy);

  if (!(dst->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_dlog_copy);
  if (pbcext_element_Fr_set(dst->s, src->s) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_copy);

 spk_dlog_copy_end:

  if (rc == IERROR) {
    if (dst->c) { pbcext_element_Fr_free(dst->c); dst->c = NULL; }
    if (dst->s) { pbcext_element_Fr_free(dst->s); dst->s = NULL; }
  }

  return rc;
  
}

int spk_dlog_G1_sign(spk_dlog_t *pi,
		     pbcext_element_G1_t *G,
		     pbcext_element_G1_t *g,
		     pbcext_element_Fr_t *x,
		     byte_t *msg,
		     uint32_t size) {
  
  pbcext_element_Fr_t *c, *s, *r, *cx;
  pbcext_element_G1_t *gr;
  byte_t *bG, *bg, *bgr;
  hash_t *hc;
  uint64_t len;
  int rc;
  
  if (!pi || !G || !g || !x || !msg || !size) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_G1_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  bG = NULL; bg = NULL; bgr = NULL;
  hc = NULL;
  rc = IOK;

  /* Pick random r and compute g^r mod q */
  r = pbcext_element_Fr_init();
  pbcext_element_Fr_random(r);
  gr = pbcext_element_G1_init();
  pbcext_element_G1_mul(gr, g, r);
  
  /* Make hc = Hash(msg||G||g||g^r) */
  if(!(hc = hash_init(HASH_SHA1))) GOTOENDRC(IERROR, spk_dlog_G1_sign);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_sign);
  if(pbcext_element_G1_to_bytes(&bG, &len, G) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_sign);
  if(hash_update(hc, bG, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_sign);
  if(pbcext_element_G1_to_bytes(&bg, &len, g) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_sign);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_sign);
  if(pbcext_element_G1_to_bytes(&bgr, &len, gr) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_sign);
  if(hash_update(hc, bgr, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_sign);
			       
  /* Convert the hash to an integer */
  c = pbcext_element_Fr_init();
  pbcext_element_Fr_from_hash(c, hc->hash, hc->length);
  
  /* s = r - cx */
  cx = pbcext_element_Fr_init();
  pbcext_element_Fr_mul(cx, c, x);
  s = pbcext_element_Fr_init();
  pbcext_element_Fr_sub(s, r, cx);
  
  /* pi = (s,c) */
  pi->s = pbcext_element_Fr_init();
  pbcext_element_Fr_set(pi->s, s);
  pi->c = pbcext_element_Fr_init();
  pbcext_element_Fr_set(pi->c, c);
  
 spk_dlog_G1_sign_end:

  pbcext_element_Fr_free(c);
  pbcext_element_Fr_free(cx);
  pbcext_element_Fr_free(s);
  pbcext_element_Fr_free(r);
  pbcext_element_G1_free(gr);
  if(bG) mem_free(bG);
  if(bg) mem_free(bg);
  if(bgr) mem_free(bgr);
  if(hc) { hash_free(hc); hc = NULL; }
  
  return rc;
  
}

int spk_dlog_G1_verify(uint8_t *ok,
		       pbcext_element_G1_t *G,
		       pbcext_element_G1_t *g,
		       spk_dlog_t *pi,
		       byte_t *msg,
		       uint32_t size) {

  pbcext_element_G1_t *gs, *Gc, *gsGc;
  pbcext_element_Fr_t *c;
  byte_t *bG, *bg, *bgsGc;
  hash_t *hc;
  uint64_t len;
  int rc;

  if (!ok || !G || !g || !pi || !msg || !size) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_G1_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  bG = NULL; bg = NULL; bgsGc = NULL;
  rc = IOK;
  
  /* If pi is correct, then pi->c must equal Hash(msg||G||g||g^pi->s*g^pi->c) */

  /* Compute g^pi->s * g^pi->c */
  gs = pbcext_element_G1_init();
  pbcext_element_G1_mul(gs, g, pi->s);
  Gc = pbcext_element_G1_init();
  pbcext_element_G1_mul(Gc, G, pi->c);
  gsGc = pbcext_element_G1_init();
  pbcext_element_G1_add(gsGc, gs, Gc);
  
  /* Compute the hash */
  if(!(hc = hash_init(HASH_SHA1))) GOTOENDRC(IERROR, spk_dlog_G1_verify);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_verify);
  if(pbcext_element_G1_to_bytes(&bG, &len, G) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_G1_verify);
  if(hash_update(hc, bG, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_verify);
  if(pbcext_element_G1_to_bytes(&bg, &len, g) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_G1_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_verify);
  if(pbcext_element_G1_to_bytes(&bgsGc, &len, gsGc) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_G1_verify);
  if(hash_update(hc, bgsGc, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_verify);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, spk_dlog_G1_verify);

  /* Compare the result with c */
  c = pbcext_element_Fr_init();
  pbcext_element_Fr_from_hash(c, hc->hash, hc->length);

  if(pbcext_element_Fr_cmp(c, pi->c)) {
    *ok = 0;
  } else {
    *ok = 1;
  }
    
 spk_dlog_G1_verify_end:
  pbcext_element_Fr_free(c);  
  pbcext_element_G1_free(gs);
  pbcext_element_G1_free(Gc);
  pbcext_element_G1_free(gsGc);
  if(bG) { mem_free(bG); bG = NULL; }
  if(bg) { mem_free(bg); bg = NULL; }
  if(bgsGc) { mem_free(bgsGc); bgsGc = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  
  return rc;
  
}

int spk_dlog_GT_sign(spk_dlog_t *pi,
		     pbcext_element_GT_t *G,
		     pbcext_element_GT_t *g,
		     pbcext_element_Fr_t *x,
		     byte_t *msg,
		     uint32_t size) {
  
  pbcext_element_Fr_t *c, *s, *r, *cx;
  pbcext_element_GT_t *gr;
  byte_t *bG, *bg, *bgr;
  hash_t *hc;
  uint64_t len;
  int rc;
  
  if (!pi || !G || !g || !x || !msg || !size) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_GT_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  bG = NULL; bg = NULL; bgr = NULL;
  hc = NULL;
  rc = IOK;

  /* Pick random r and compute g^r mod q */
  r = pbcext_element_Fr_init();
  pbcext_element_Fr_random(r);
  gr = pbcext_element_GT_init();
  pbcext_element_GT_pow(gr, g, r);
  
  /* Make hc = Hash(msg||G||g||g^r) */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, spk_dlog_GT_sign);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_sign);
  if(pbcext_element_GT_to_bytes(&bG, &len, G) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_sign);
  if(hash_update(hc, bG, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_sign);
  if(pbcext_element_GT_to_bytes(&bg, &len, g) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_sign);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_sign);
  if(pbcext_element_GT_to_bytes(&bgr, &len, gr) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_sign);
  if(hash_update(hc, bgr, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_sign);
			       
  /* Convert the hash to an integer */
  c = pbcext_element_Fr_init();
  pbcext_element_Fr_from_hash(c, hc->hash, hc->length);
  
  /* s = r - cx */
  cx = pbcext_element_Fr_init();
  pbcext_element_Fr_mul(cx, c, x);
  s = pbcext_element_Fr_init();
  pbcext_element_Fr_sub(s, r, cx);
  
  /* pi = (s,c) */
  pi->s = pbcext_element_Fr_init();
  pbcext_element_Fr_set(pi->s, s);
  pi->c = pbcext_element_Fr_init();
  pbcext_element_Fr_set(pi->c, c);
  
 spk_dlog_GT_sign_end:

  pbcext_element_Fr_free(c);
  pbcext_element_Fr_free(cx);
  pbcext_element_Fr_free(s);
  pbcext_element_Fr_free(r);
  pbcext_element_GT_free(gr);
  if(bG) mem_free(bG);
  if(bg) mem_free(bg);
  if(bgr) mem_free(bgr);
  if(hc) { hash_free(hc); hc = NULL; }
  
  return rc;
  
}

int spk_dlog_GT_verify(uint8_t *ok,
		       pbcext_element_GT_t *G,
		       pbcext_element_GT_t *g,
		       spk_dlog_t *pi,
		       byte_t *msg,
		       uint32_t size) {

  pbcext_element_GT_t *gs, *Gc, *gsGc;
  pbcext_element_Fr_t *c;
  byte_t *bG, *bg, *bgsGc;
  hash_t *hc;
  uint64_t len;
  int rc;

  if (!ok || !G || !g || !pi || !msg || !size) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_GT_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  bG = NULL; bg = NULL; bgsGc = NULL;
  rc = IOK;
  
  /* If pi is correct, then pi->c must equal Hash(msg||G||g||g^pi->s*g^pi->c) */

  /* Compute g^pi->s * g^pi->c */
  gs = pbcext_element_GT_init();
  pbcext_element_GT_pow(gs, g, pi->s);
  Gc = pbcext_element_GT_init();
  pbcext_element_GT_pow(Gc, G, pi->c);
  gsGc = pbcext_element_GT_init();
  pbcext_element_GT_mul(gsGc, gs, Gc);
  
  /* Compute the hash */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, spk_dlog_GT_verify);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_verify);
  if(pbcext_element_GT_to_bytes(&bG, &len, G) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_GT_verify);
  if(hash_update(hc, bG, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_verify);
  if(pbcext_element_GT_to_bytes(&bg, &len, g) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_GT_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_verify);
  if(pbcext_element_GT_to_bytes(&bgsGc, &len, gsGc) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_GT_verify);
  if(hash_update(hc, bgsGc, len) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_verify);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, spk_dlog_GT_verify);

  /* Compare the result with c */
  c = pbcext_element_Fr_init();
  pbcext_element_Fr_from_hash(c, hc->hash, hc->length);

  if(pbcext_element_Fr_cmp(c, pi->c)) {
    *ok = 0;
  } else {
    *ok = 1;
  }
    
 spk_dlog_GT_verify_end:
  pbcext_element_Fr_free(c);  
  pbcext_element_GT_free(gs);
  pbcext_element_GT_free(Gc);
  pbcext_element_GT_free(gsGc);
  if(bG) { mem_free(bG); bG = NULL; }
  if(bg) { mem_free(bg); bg = NULL; }
  if(bgsGc) { mem_free(bgsGc); bgsGc = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  
  return rc;
  
}

int spk_dlog_get_size(spk_dlog_t *proof) {

  uint64_t ss, sc, size;

  if(!proof) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_get_size", __LINE__,
	       LOGERROR);
    return -1;
  }
  
  /* size = sizeof(c) + c + sizeof(s) + s */
  if(pbcext_element_Fr_byte_size(&ss) == -1) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == -1) return -1;
  
  // I do not like this uncontrolled cast...
  size = (int) 2*sizeof(int) + ss + sc;
  if (size > INT_MAX) return -1;

  return (int) size;
  
}

int spk_dlog_export_fd(spk_dlog_t *proof, FILE *fd) {
  
  if(!proof || !fd) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_export_fd", __LINE__, LOGERROR);
    return IERROR;
  }
    
  if(!proof->c || !proof->s) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_export_fd", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Dump s */
  if(pbcext_dump_element_Fr_fd(proof->s, fd) == IERROR) {
    return IERROR;
  }

  /* Dump c */
  if(pbcext_dump_element_Fr_fd(proof->c, fd) == IERROR) {
    return IERROR;
  }
  
  return IOK;
  
}

int spk_dlog_export(byte_t **bytes,
		    uint64_t *len,
		    spk_dlog_t *proof) {

  byte_t *bs, *bc, *_bytes;
  uint64_t slen, clen;
  int rc;

  if (!bytes || !len || !proof) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_export", __LINE__, LOGERROR);
    return IERROR;
  }

  bs = bc = _bytes = NULL;
  rc = IOK;
  
  if(pbcext_dump_element_Fr_bytes(&bs, &slen, proof->s) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_export);

  if(pbcext_dump_element_Fr_bytes(&bc, &clen, proof->c) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_export);

  if(!(_bytes = (byte_t *) mem_malloc(sizeof(byte_t)*(slen+clen))))
    GOTOENDRC(IERROR, spk_dlog_export);
  
  memcpy(_bytes, bs, slen);
  memcpy(&_bytes[slen], bc, clen);
  
  if(!*bytes) *bytes = _bytes;
  else {
    memcpy(*bytes, _bytes, sizeof(byte_t)*(slen+clen));
    mem_free(_bytes); _bytes = NULL;
  }
  *len = slen + clen;

 spk_dlog_export_end:
  
  if(bs) { mem_free(bs); bs = NULL; }
  if(bc) { mem_free(bc); bc = NULL; }
  
  return rc;
  
}

spk_dlog_t* spk_dlog_import_fd(FILE *fd) {

  spk_dlog_t *proof;
  bool read;
  int rc;

  if(!fd) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_import_fd", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(proof = spk_dlog_init())) {
    return NULL;
  }

  rc = IOK;

  /* Get s */
  if(!(proof->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_dlog_import_fd);
  if(pbcext_get_element_Fr_fd(proof->s, &read, fd) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_import_fd);

  /* Get c */
  if(!(proof->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_dlog_import_fd);
  if(pbcext_get_element_Fr_fd(proof->c, &read, fd) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_import_fd);

 spk_dlog_import_fd_end:

  if(rc == IERROR && proof) { spk_dlog_free(proof); proof = NULL; }
  
  return proof;

}

spk_dlog_t* spk_dlog_import(byte_t *bytes, uint64_t *len) {

  spk_dlog_t *proof;
  uint64_t _len;
  int rc;

  if(!bytes || !len) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(proof = spk_dlog_init())) {
    return NULL;
  }

  rc = IOK;

  /* Get s */
  if(!(proof->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_dlog_import);
  if(pbcext_get_element_Fr_bytes(proof->s, &_len, bytes) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_import);
  *len = _len;

  /* Get c */
  if(!(proof->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_dlog_import);
  if(pbcext_get_element_Fr_bytes(proof->c, &_len, &bytes[*len]) == IERROR)
    GOTOENDRC(IERROR, spk_dlog_import);
  *len += _len;

 spk_dlog_import_end:

  if(rc == IERROR && proof) { spk_dlog_free(proof); proof = NULL; }
  
  return proof;  
  
}

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

int spk_rep_copy(spk_rep_t *dst, spk_rep_t *src) {

  int rc;
  uint16_t i;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "spk_rep_sign", __LINE__, LOGERROR);
    return IERROR;   
  }

  rc = IOK;
  
  if (!(dst->c = pbcext_element_Fr_init())) return IERROR;
  if (pbcext_element_Fr_set(dst->c, src->c) == IERROR)
    GOTOENDRC(IERROR, spk_rep_copy);
  
  for (i=0; i<src->ns; i++) {
    if (!(dst->s[i] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, spk_rep_copy);
    if (pbcext_element_Fr_set(dst->s[i], src->s[i]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_copy);
  }
  
 spk_rep_copy_end:

  if (rc == IERROR) {
    if (dst->c) { pbcext_element_Fr_free(dst->c); dst->c = NULL; }
    for (i=0; i<src->ns; i++) {
      if (dst->s[i]) { pbcext_element_Fr_free(dst->s[i]); dst->s[i] = NULL; }
    }
  }
  
  return rc;
  
}

int spk_rep_get_size(spk_rep_t *proof) {

  uint64_t ss, sc, size64;
  uint16_t i;

  if(!proof) {
    LOG_EINVAL(&logger, __FILE__, "spk_dlog_get_size", __LINE__,
	       LOGERROR);
    return -1;
  }

  size64 = sizeof(uint16_t);
  
  /* size = sizeof(c) + c + sizeof(s) + s */
  if(pbcext_element_Fr_byte_size(&sc) == -1) return -1;
  size64 += sc+sizeof(int);

  if(pbcext_element_Fr_byte_size(&ss) == -1) return -1;
  size64 += (proof->ns*(ss+sizeof(int)));
  
  if (size64 > INT_MAX) return -1;

  return (int) size64;
  
}

int spk_rep_export(byte_t **bytes,
		   uint64_t *len,
		   spk_rep_t *proof) {
  
  byte_t *_bytes, *__bytes;
  uint64_t size, _len, offset;
  int rc;
  uint16_t i;

  if (!bytes || !len || !proof) {
    LOG_EINVAL(&logger, __FILE__, "spk_rep_export", __LINE__, LOGERROR);
    return IERROR;
  }

  _bytes = NULL;
  offset = 0;
  rc = IOK;
  
  if ((size = spk_rep_get_size(proof)) == -1)
    GOTOENDRC(IERROR, spk_rep_export);

  if (!(_bytes = (byte_t *) mem_malloc(sizeof(byte_t)*size)))
    GOTOENDRC(IERROR, spk_rep_export);

  __bytes = _bytes;
  if(pbcext_dump_element_Fr_bytes(&__bytes, &_len, proof->c) == IERROR)
    GOTOENDRC(IERROR, spk_rep_export);
  offset += _len;

  memcpy(&_bytes[offset], &proof->ns, sizeof(uint16_t));
  offset += sizeof(uint16_t);
  
  for (i=0; i<proof->ns; i++) {
    __bytes = &_bytes[offset];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &_len, proof->s[i]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_export);      
    offset += _len;
  }

  *len = offset;

  if (!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, offset);
    mem_free(_bytes); _bytes = NULL;
  }

 spk_rep_export_end:

  if (rc == IERROR) {
    if (_bytes) { mem_free(_bytes); _bytes = NULL; }
  }
  
  return rc;
  
}

spk_rep_t* spk_rep_import(byte_t *bytes, uint64_t *len) {

  spk_rep_t *proof;
  pbcext_element_Fr_t *c;
  uint64_t _len, offset;
  int rc;
  uint16_t i, ns;

  if(!bytes || !len) {
    LOG_EINVAL(&logger, __FILE__, "spk_rep_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  rc = IOK;
  c = NULL;

  /* Get c */
  if(!(c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_rep_import);
  if(pbcext_get_element_Fr_bytes(c, &_len, bytes) == IERROR)
    GOTOENDRC(IERROR, spk_rep_import);
  offset = _len;

  /* Get ns */
  memcpy(&ns, &bytes[offset], sizeof(uint16_t));
  offset += sizeof(uint16_t);

  if(!(proof = spk_rep_init(ns))) GOTOENDRC(IERROR, spk_rep_import);

  proof->c = c;

  /* Get the s[i]'s */
  for(i=0; i<proof->ns; i++) {
    if(!(proof->s[i] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, spk_rep_import);
    if(pbcext_get_element_Fr_bytes(proof->s[i], &_len, &bytes[offset]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_import);
    offset += _len;
  }

  *len = offset;

 spk_rep_import_end:

  if(rc == IERROR && proof) {
    spk_rep_free(proof); proof = NULL;
    if (c) { pbcext_element_Fr_free(c); c = NULL; }
  }
  
  return proof;  
  
}

int spk_rep_sign(spk_rep_t *pi,
		 pbcext_element_G1_t *y[], uint16_t ny,
		 pbcext_element_G1_t *g[], uint16_t ng,
		 pbcext_element_Fr_t *x[], uint16_t nx,
		 uint16_t i[][2], uint16_t ni,
		 uint16_t *prods,
		 byte_t *msg, uint32_t size) {

  pbcext_element_Fr_t **r, *cx;
  pbcext_element_G1_t **prod, **gr;
  byte_t *by, *bg, *bprod, bi[4];
  hash_t *hc;
  uint64_t len;
  int rc;
  uint16_t j, k, l;
  
  if (!pi || !y || !g || !x || !i || !prods || !msg ||
      ny <= 0 || ng <= 0 || nx <= 0 || ni <= 0 || size <= 0) {
    LOG_EINVAL(&logger, __FILE__, "spk_rep_sign", __LINE__, LOGERROR);
    return IERROR;   
  }

  r = NULL; prod = NULL; gr = NULL;
  by = NULL; bg = NULL; bprod = NULL;
  hc = NULL;
  rc = IOK;
  
  /* Allocate auxiliar structures */
  if(!(r = (pbcext_element_Fr_t **)
       mem_malloc(sizeof(pbcext_element_Fr_t *)*nx)))
    GOTOENDRC(IERROR, spk_rep_sign);
  if(!(prod = (pbcext_element_G1_t **)
       mem_malloc(sizeof(pbcext_element_G1_t *)*ny)))
    GOTOENDRC(IERROR, spk_rep_sign);
  if(!(gr = (pbcext_element_G1_t **)
       mem_malloc(sizeof(pbcext_element_G1_t *)*ni)))
    GOTOENDRC(IERROR, spk_rep_sign);

  /* All loops in this function can probably be unified and make all 
     more efficient... */
  for(j=0; j<nx; j++) {
    r[j] = pbcext_element_Fr_init();
    pbcext_element_Fr_random(r[j]);
  }

  /* Compute the challenges according to the relations defined by 
     the i indexes */
  for(j=0; j<ni; j++) {
    gr[j] = pbcext_element_G1_init();
    pbcext_element_G1_mul(gr[j], g[i[j][1]], r[i[j][0]]);
  }

  /* Compute the challenge products */
  l  = 0; /* l will end up being ni-1 */
  for(j=0; j<ny; j++) {
    
    prod[j] = pbcext_element_G1_init();
    pbcext_element_G1_set(prod[j], gr[l]);
    l++;
    
    if (prods[j] > 1) {

      /* We use prods to specify how the i indexes are 'assigned' per 
	 random 'challenge' */
      for(k=0; k<prods[j]-1; k++) {
	pbcext_element_G1_add(prod[j], prod[j], gr[l]);
	l++;	
      }

    }
    
  }

  /* 
     Compute the hash:

     pi->c = Hash(msg, y[1..ny], g[1..ng], i[1,1], i[1,2] .. i[ni,1], i[ni,2], prod[1..ny]) 
     
     where prod[j] = g[i[j,2]]^r[i[j,1]]
  */

  /* Push the message */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, spk_rep_sign);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, spk_rep_sign);
  
  /* Push the y values */
  for(j=0; j<ny; j++) {
    by = NULL;
    if(pbcext_element_G1_to_bytes(&by, &len, y[j]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_sign);
    if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, spk_rep_sign);
    mem_free(by); by = NULL;
  }

  /* Push the base values */
  for(j=0; j<ng; j++) {
    bg = NULL;
    if(pbcext_element_G1_to_bytes(&bg, &len, g[j]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_sign);
    if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_rep_sign);
    mem_free(bg); bg = NULL;
  }

  /* Push the indices */
  for(j=0; j<ni; j++) {
    memset(bi, 0, 4);
    bi[0] = i[j][0] & 0xFF;
    bi[1] = (i[j][0] & 0xFF00) >> 8;
    bi[2] = i[j][1] & 0xFF;
    bi[3] = (i[j][1] & 0xFF00) >> 8;
    if(hash_update(hc, bi, 4) == IERROR) GOTOENDRC(IERROR, spk_rep_sign);
  }

  /* Push the products */
  for(j=0; j<ny; j++) {
    bprod = NULL;
    if(pbcext_element_G1_to_bytes(&bprod, &len, prod[j]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_sign);
    if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, spk_rep_sign);
    mem_free(bprod); bprod = NULL;
  }
  
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, spk_rep_sign);

  /* Convert the hash to an integer */
  pi->c = pbcext_element_Fr_init();
  pbcext_element_Fr_from_hash(pi->c, hc->hash, hc->length);

  /* Compute challenge responses */
  cx = pbcext_element_Fr_init();

  for(j=0; j<pi->ns; j++) {
    
    /* si = ri - cxi */    
    pbcext_element_Fr_mul(cx, pi->c, x[j]);
    pi->s[j] = pbcext_element_Fr_init();
    pbcext_element_Fr_sub(pi->s[j], r[j], cx);
  
  }
  
 spk_rep_sign_end:

  pbcext_element_Fr_free(cx);
  
  if(r) {
    for(j=0; j<nx; j++) {
      pbcext_element_Fr_free(r[j]);
    }
    mem_free(r); r = NULL;
  }
  
  if(prod) {
    for(j=0; j<ny; j++) {
      pbcext_element_G1_free(prod[j]);
    }
    mem_free(prod); prod = NULL;
  }

  if(gr) {
    for(j=0; j<ni; j++) {
      pbcext_element_G1_free(gr[j]);
    }
    mem_free(gr); gr = NULL;
  }

  if(by) { mem_free(by); by = NULL; }
  if(bg) { mem_free(bg); bg = NULL; }
  if(bprod) { mem_free(bprod); bprod = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
	  
  return rc;
	  
}

int spk_rep_verify(uint8_t *ok,
		   pbcext_element_G1_t *y[], uint16_t ny,
		   pbcext_element_G1_t *g[], uint16_t ng,
		   uint16_t i[][2], uint16_t ni,
		   uint16_t *prods,
		   spk_rep_t *pi,
		   byte_t *msg, uint32_t size) {

  pbcext_element_Fr_t *c;
  pbcext_element_G1_t **prod, *gs;
  byte_t *by, *bg, *bprod, bi[4];
  hash_t *hc;
  uint64_t len;
  int rc;
  uint16_t j, k, l;
	  
  if (!ok || !y || !g || !i || !prods || !pi || !msg ||
      ny <= 0 || ng <= 0 || ni <= 0 || size <= 0) {
    LOG_EINVAL(&logger, __FILE__, "spk_rep_verify", __LINE__, LOGERROR);
    return IERROR;   
  }

  prod = NULL;
  by = NULL; bg = NULL; bprod = NULL;
  hc = NULL;
  rc = IOK;

  /* Allocate auxiliar structures */
  if(!(prod = (pbcext_element_G1_t **)
       mem_malloc(sizeof(pbcext_element_G1_t *)*ny)))
    GOTOENDRC(IERROR, spk_rep_verify);
	  
  /* Compute the challenge products */
  l  = 0; /* l will end up being ni-1 */
  gs = pbcext_element_G1_init();
  for(j=0; j<ny; j++) {

    prod[j] = pbcext_element_G1_init();
    pbcext_element_G1_mul(prod[j], y[j], pi->c);

    if (prods[j] >= 1) {

      /* We use prods to specify how the i indexes are 'assigned' per 
	 random 'challenge' */
      for(k=0; k<prods[j]; k++) {
	pbcext_element_G1_mul(gs, g[i[l][1]], pi->s[i[l][0]]);

	pbcext_element_G1_add(prod[j], prod[j], gs);
	l++;	
      }

    }
	    
  }
	  
  /* 
     if pi is correct, then pi->c must equal:

     Hash(msg, y[1..ny], g[1..ng], i[1,1], i[1,2] .. i[ni,1], i[ni,2], prod[1..ny]) 

     where prod[j] = y[j]^c*g[i[j,2]]^s[i[j,1]]
  */

  /* Push the message */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, spk_rep_verify);
  if(hash_update(hc, msg, size) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);

  /* Push the y values */
  for(j=0; j<ny; j++) {
    by = NULL;
    if(pbcext_element_G1_to_bytes(&by, &len, y[j]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_verify);
    if(hash_update(hc, by, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
    mem_free(by); by = NULL;
  }

  /* Push the base values */
  for(j=0; j<ng; j++) {
    bg = NULL;
    if(pbcext_element_G1_to_bytes(&bg, &len, g[j]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_verify);
    if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
    mem_free(bg); bg = NULL;
  }

  /* Push the indices */
  for(j=0; j<ni; j++) {
    memset(bi, 0, 4);
    bi[0] = i[j][0] & 0xFF;
    bi[1] = (i[j][0] & 0xFF00) >> 8;
    bi[2] = i[j][1] & 0xFF;
    bi[3] = (i[j][1] & 0xFF00) >> 8;
    if(hash_update(hc, bi, 4) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
  }

  /* Push the products */
  for(j=0; j<ny; j++) {
    bprod = NULL;
    if(pbcext_element_G1_to_bytes(&bprod, &len, prod[j]) == IERROR)
      GOTOENDRC(IERROR, spk_rep_verify);
    if(hash_update(hc, bprod, len) == IERROR) GOTOENDRC(IERROR, spk_rep_verify);
    mem_free(bprod); bprod = NULL;
  }
	  
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

  pbcext_element_Fr_free(c);
  pbcext_element_G1_free(gs);

  if(prod) {
    for(j=0; j<ny; j++) {
      pbcext_element_G1_free(prod[j]);
    }
    mem_free(prod); prod = NULL;
  }
	    
  if(by) { mem_free(by); by = NULL; }
  if(bg) { mem_free(bg); bg = NULL; }
  if(bprod) { mem_free(bprod); bprod = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
	  
  return rc;
	  
}

spk_pairing_homomorphism_G2_t* spk_pairing_homomorphism_G2_init() {

  spk_pairing_homomorphism_G2_t *spk;

  if(!(spk = (spk_pairing_homomorphism_G2_t *)
       mem_malloc(sizeof(spk_pairing_homomorphism_G2_t)))) {
    return NULL;
  }

  return spk;
  
}

int spk_pairing_homomorphism_G2_free(spk_pairing_homomorphism_G2_t *spk) {

  if(!spk) {
    LOG_EINVAL_MSG(&logger, __FILE__, "spk_pairing_homomorphism_G2_free",
		   __LINE__, "Nothing to free.", LOGWARN);
    return IERROR;
  }

  pbcext_element_Fr_free(spk->c); spk->c = NULL;
  pbcext_element_G2_free(spk->s); spk->s = NULL;
  mem_free(spk); spk = NULL;

  return IOK;
  
}

int spk_pairing_homomorphism_G2_sign(spk_pairing_homomorphism_G2_t *pi,
				     pbcext_element_G1_t *g,
				     pbcext_element_GT_t *G,
				     pbcext_element_G2_t *xx,
				     byte_t *msg,
				     uint32_t size) {
  
  pbcext_element_Fr_t *c;
  pbcext_element_G2_t *rr, *ss;
  pbcext_element_GT_t *R;
  byte_t *bg, *bG, *bR;
  hash_t *hc;
  uint64_t len;
  int rc;
  
  if (!pi || !g || !G || !xx || !msg || !size) {
    LOG_EINVAL(&logger, __FILE__, "spk_pairing_homomorphism_G2_sign",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  c = NULL;
  rr = ss = NULL;
  R = NULL;
  bg = NULL; bG = NULL; bR = NULL;
  hc = NULL;
  rc = IOK;

  /* Pick random R from G2 */
  if (!(rr = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if (pbcext_element_G2_random(rr) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);

  /* Compute the map */
  if (!(R = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if (pbcext_pairing(R, g, rr) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);    
  
  /* Make hc = Hash(msg||g||G||R) */
  if(!(hc = hash_init(HASH_BLAKE2)))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if(hash_update(hc, msg, size) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if(pbcext_element_G1_to_bytes(&bg, &len, g) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if(hash_update(hc, bg, len) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if(pbcext_element_GT_to_bytes(&bG, &len, G) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if(hash_update(hc, bG, len) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if(pbcext_element_GT_to_bytes(&bR, &len, R) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if(hash_update(hc, bR, len) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if(hash_finalize(hc) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
			       
  /* Convert the hash to an integer */
  if (!(c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if (pbcext_element_Fr_from_hash(c, hc->hash, hc->length) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  
  /* ss = rr+c*xx */
  if (!(ss = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if (pbcext_element_G2_mul(ss, xx, c) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
  if (pbcext_element_G2_add(ss, rr, ss) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);
    
  /* pi = (s,c) */
  if (!(pi->s = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);    
  if (pbcext_element_G2_set(pi->s, ss) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);    
  if (!(pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);    
  if (pbcext_element_Fr_set(pi->c, c) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_sign);    

 spk_pairing_homomorphism_G2_sign_end:

  if (c) { pbcext_element_Fr_free(c); c = NULL; }
  if (rr) { pbcext_element_G2_free(rr); rr = NULL; }
  if (ss) { pbcext_element_G2_free(ss); ss = NULL; }
  if (R) { pbcext_element_GT_free(R); R = NULL; }
  if (bg) { mem_free(bg); bg = NULL; }
  if (bG) { mem_free(bG); bG = NULL; }
  if (bR) { mem_free(bR); bR = NULL; }
  if (hc) { hash_free(hc); hc = NULL; }
  
  return rc;
  
}

int spk_pairing_homomorphism_G2_verify(uint8_t *ok,
				       pbcext_element_G1_t *g,
				       pbcext_element_GT_t *G,
				       spk_pairing_homomorphism_G2_t *pi,
				       byte_t *msg,
				       uint32_t size) {
  
  pbcext_element_GT_t *R, *Gc;
  pbcext_element_Fr_t *c;
  byte_t *bg, *bG, *bR;
  hash_t *hc;
  uint64_t len;
  int rc;

  if (!ok || !g || !G || !pi || !msg || !size) {
    LOG_EINVAL(&logger, __FILE__, "spk_pairing_homomorphism_G2_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  R = Gc = NULL;
  bg = NULL; bG = NULL; bR = NULL;
  rc = IOK;
  
  /* If pi is correct, then pi->c equals Hash(msg||g||G||e(g,pi->ss)/G^pi->c) */

  /* Compute e(g,pi->ss)/G^pi->c */
  if (!(Gc = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if (pbcext_element_GT_pow(Gc, G, pi->c) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if (!(R = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if (pbcext_pairing(R, g, pi->s) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if (pbcext_element_GT_div(R, R, Gc) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);    

  /* Compute the hash */
  if(!(hc = hash_init(HASH_BLAKE2)))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if(hash_update(hc, msg, size) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if(pbcext_element_G1_to_bytes(&bg, &len, g) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if(hash_update(hc, bg, len) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if(pbcext_element_GT_to_bytes(&bG, &len, G) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if(hash_update(hc, bG, len) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if(pbcext_element_GT_to_bytes(&bR, &len, R) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if(hash_update(hc, bR, len) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if(hash_finalize(hc) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);

  /* Compare the result with c */
  if (!(c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);
  if (pbcext_element_Fr_from_hash(c, hc->hash, hc->length) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_verify);

  if(pbcext_element_Fr_cmp(c, pi->c)) {
    *ok = 0;
  } else {
    *ok = 1;
  }

 spk_pairing_homomorphism_G2_verify_end:
  
  if (c) { pbcext_element_Fr_free(c); c = NULL; }
  if (Gc) { pbcext_element_GT_free(Gc); Gc = NULL; }
  if (R) { pbcext_element_GT_free(R); R = NULL; }
  if(bg) { mem_free(bg); bg = NULL; }
  if(bG) { mem_free(bG); bG = NULL; }  
  if(bR) { mem_free(bR); bR = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  
  return rc;
  
}

int spk_pairing_homomorphism_G2_get_size(spk_pairing_homomorphism_G2_t *proof) {

  uint64_t ss, sc, size;

  if(!proof) {
    LOG_EINVAL(&logger, __FILE__, "spk_pairing_homomorphism_G2_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }
  
  /* size = sizeof(c) + c + sizeof(s) + s */
  if(pbcext_element_G2_byte_size(&ss) == -1) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == -1) return -1;
  
  // I do not like this uncontrolled cast...
  size = (int) 2*sizeof(int) + ss + sc;
  if (size > INT_MAX) return -1;

  return (int) size;
  
}

int
spk_pairing_homomorphism_G2_export(byte_t **bytes,
				   uint64_t *len,
				   spk_pairing_homomorphism_G2_t *proof) {

  byte_t *bs, *bc, *_bytes;
  uint64_t slen, clen, _len;

  if (!bytes || !len || !proof) {
    LOG_EINVAL(&logger, __FILE__, "spk_pairing_homomorphism_G2_export",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  bs = bc = _bytes = NULL;
  if(pbcext_dump_element_G2_bytes(&bs, &slen, proof->s) == IERROR) 
    return IERROR;

  if(pbcext_dump_element_Fr_bytes(&bc, &clen, proof->c) == IERROR) 
    return IERROR;

  if(!(_bytes = (byte_t *) mem_malloc(sizeof(byte_t)*(slen+clen)))) {
    mem_free(bc); bc = NULL;
    mem_free(bs); bs = NULL;
    return IERROR;
  }
  
  memcpy(_bytes, bs, slen);
  memcpy(&_bytes[slen], bc, clen);
  
  if(!*bytes) *bytes = _bytes;
  else {
    memcpy(*bytes, _bytes, sizeof(byte_t)*(slen+clen));
    mem_free(_bytes); _bytes = NULL;
  }
  *len = slen + clen;

  if(bs) { mem_free(bs); bs = NULL; }
  if(bc) { mem_free(bc); bc = NULL; }
  
  return IOK;
  
}

spk_pairing_homomorphism_G2_t*
spk_pairing_homomorphism_G2_import(byte_t *bytes, uint64_t *len) {

  spk_pairing_homomorphism_G2_t *proof;
  uint64_t _len;
  int rc;

  if(!bytes || !len) {
    LOG_EINVAL(&logger, __FILE__, "spk_pairing_homomorphism_G2_import",
	       __LINE__, LOGERROR);
    return NULL;
  }

  if(!(proof = spk_pairing_homomorphism_G2_init())) {
    return NULL;
  }

  rc = IOK;

  /* Get s */
  if(!(proof->s = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_import);
  if(pbcext_get_element_G2_bytes(proof->s, &_len, bytes) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_import);
  *len = _len;

  /* Get c */
  if(!(proof->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_import);
  if(pbcext_get_element_Fr_bytes(proof->c, &_len, &bytes[*len]) == IERROR)
    GOTOENDRC(IERROR, spk_pairing_homomorphism_G2_import);
  *len += _len;

 spk_pairing_homomorphism_G2_import_end:

  if(rc == IERROR && proof) {
    spk_pairing_homomorphism_G2_free(proof);
    proof = NULL;
  }
  
  return proof;  
  
}
