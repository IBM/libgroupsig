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

#include "prf.h"
#include "sys/mem.h"

prf_key_t* prf_key_init() {

  prf_key_t *key;
  
  if (!(key = (prf_key_t *) mem_malloc(sizeof(prf_key_t)))) {
    return NULL;
  }

  if(!(key->g = pbcext_element_G1_init())) {
    mem_free(key); key = NULL;
    return NULL;
  }

  if(!(key->k = pbcext_element_Fr_init())) {
    mem_free(key); key = NULL;
    return NULL;
  }

  return key;
  
}

prf_key_t* prf_key_init_random() {

  prf_key_t *key;
  
  if (!(key = (prf_key_t *) mem_malloc(sizeof(prf_key_t)))) {
    return NULL;
  }

  if (!(key->g = pbcext_element_G1_init())) {
    mem_free(key); key = NULL;
    return NULL;
  }

  if (pbcext_element_G1_random(key->g) == IERROR) {
    pbcext_element_G1_free(key->g); key->g = NULL;
    mem_free(key); key = NULL;
    return NULL;
  }

  if (!(key->k = pbcext_element_Fr_init())) {
    mem_free(key); key = NULL;
    return NULL;
  }

  if (pbcext_element_Fr_random(key->k) == IERROR) {
    pbcext_element_G1_free(key->g); key->g = NULL;
    pbcext_element_Fr_free(key->k); key->k = NULL;
    mem_free(key); key = NULL;
    return NULL;
  }

  return key;
  
}

int prf_key_free(prf_key_t *key) {

  if (!key) return IOK;

  if (key->g) { pbcext_element_G1_free(key->g); key->g = NULL; }
  if (key->k) { pbcext_element_Fr_free(key->k); key->k = NULL; }
  mem_free(key); key = NULL;

  return IOK;

}

int prf_compute(byte_t **out, uint64_t *outlen, prf_key_t *key,
		byte_t *data, uint64_t len) {

  pbcext_element_Fr_t *x;
  pbcext_element_G1_t *g;
  byte_t *_out;
  uint64_t _len;

  if (!out || !outlen || !key || !data || !len) {
    LOG_EINVAL(&logger, __FILE__, "prf_compute", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Convert data to an Fr element (@TODO how to check for polylogarithmic 
     sizes?) */

  if (!(x = pbcext_element_Fr_init())) {
    return IERROR;
  }

  if (pbcext_element_Fr_from_unformat_bytes(x, data, len) == IERROR) {
    pbcext_element_Fr_free(x); x = NULL;
    return IERROR;
  }
  
  /* Compute key->g^{1/key->k+x} */
  if (pbcext_element_Fr_add(x, x, key->k) == IERROR) {
    pbcext_element_Fr_free(x); x = NULL;
    return IERROR;
  }

  if (pbcext_element_Fr_inv(x, x) == IERROR) {
    pbcext_element_Fr_free(x); x = NULL;
    return IERROR;
  }

  if (!(g = pbcext_element_G1_init())) {
    pbcext_element_Fr_free(x); x = NULL;
    return IERROR;
  }
  
  if (pbcext_element_G1_mul(g, key->g, x) == IERROR) {
    pbcext_element_Fr_free(x); x = NULL;
    pbcext_element_G1_free(g); g = NULL;
    return IERROR;
  }

  pbcext_element_Fr_free(x); x = NULL;
  
  /* Convert the result to bytes. If *out is not NULL, the caller
     must ensure enough size. */
  if (pbcext_element_G1_byte_size(&_len) == IERROR) {
    pbcext_element_G1_free(g); g = NULL;
    return IERROR;
  }

  _out = NULL;
  if (pbcext_element_G1_to_bytes(&_out, &_len, g) == IERROR) {
    pbcext_element_G1_free(g); g = NULL;
    return IERROR;
  }

  pbcext_element_G1_free(g); g = NULL;
  if (!*out) { *out = _out; }
  else { memcpy(*out, _out, _len); }
  *outlen = _len;

  return IOK;
  
}
