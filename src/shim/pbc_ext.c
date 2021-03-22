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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pbc_ext.h"
#include "logger.h"
#include "base64.h"
#include "sys/mem.h"
#include "misc/misc.h"

// @TODO to_string methods fixed to 1024 chars???

/** Initialization and deinitialization **/

pbcext_element_G1_t G1_GEN;
pbcext_element_G2_t G2_GEN;

int pbcext_init(int curve) {

  if (curve != MCL_BLS12_381) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_init", __LINE__, LOGERROR);
    return IERROR;
  }
  
  if (mclBn_init(curve, MCLBN_COMPILED_TIME_VAR)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "pbcext_init",
		      __LINE__, ENOLINK, "mclBn_init", LOGERROR);
    return IERROR;
  }

  if(mclBnG1_setStr(&G1_GEN, BLS12_381_P, strlen(BLS12_381_P), 10)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "pbcext_init",
		      __LINE__, ENOLINK, "mclBnG1_setStr", LOGERROR);
    return IERROR;
  }

  if(mclBnG2_setStr(&G2_GEN, BLS12_381_Q, strlen(BLS12_381_Q), 10)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "pbcext_init",
		      __LINE__, ENOLINK, "mclBnG2_setStr", LOGERROR);
    return IERROR;
  }
  
  return IOK;

}

pbcext_element_Fp_t* pbcext_element_Fp_init() {
  
  pbcext_element_Fp_t *e;
  
  if(!(e = (pbcext_element_Fp_t *) mem_malloc(sizeof(pbcext_element_Fp_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_Fp_init",
		  __LINE__, errno, LOGERROR);
    return NULL;
  }
  
  return e;
  
}

int pbcext_element_Fp_free(pbcext_element_Fp_t *e) {

  if (!e) { return IOK; }

  mclBnFp_clear(e);
  mem_free(e);
  e = NULL;
    
  return IOK;

}

pbcext_element_Fr_t* pbcext_element_Fr_init() {

  pbcext_element_Fr_t *e;
  
  if(!(e = (pbcext_element_Fr_t *) mem_malloc(sizeof(pbcext_element_Fr_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_Fr_init",
		  __LINE__, errno, LOGERROR);
    return NULL;
  }
  
  return e;

}

int pbcext_element_Fr_free(pbcext_element_Fr_t *e) {

  if (!e) { return IOK; }

  mclBnFr_clear(e);
  mem_free(e);
  e = NULL;
    
  return IOK;

}

pbcext_element_G1_t* pbcext_element_G1_init() {

  pbcext_element_G1_t *e;
  
  if(!(e = (pbcext_element_G1_t *) mem_malloc(sizeof(pbcext_element_G1_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_G1_init",
		  __LINE__, errno, LOGERROR);
    return NULL;
  }
  
  return e;

}

int pbcext_element_G1_free(pbcext_element_G1_t *e) {

  if (!e) { return IOK; }

  mclBnG1_clear(e);
  mem_free(e);
  e = NULL;
    
  return IOK;

}

pbcext_element_G2_t* pbcext_element_G2_init() {

  pbcext_element_G2_t *e;
  
  if(!(e = (pbcext_element_G2_t *) mem_malloc(sizeof(pbcext_element_G2_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_G2_init",
		  __LINE__, errno, LOGERROR);
    return NULL;
  }
  
  return e;

}

int pbcext_element_G2_free(pbcext_element_G2_t *e) {

  if (!e) { return IOK; }

  mclBnG2_clear(e);
  mem_free(e);
  e = NULL;
    
  return IOK;

}

pbcext_element_GT_t* pbcext_element_GT_init() {

  pbcext_element_GT_t *e;
  
  if(!(e = (pbcext_element_GT_t *) mem_malloc(sizeof(pbcext_element_GT_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_GT_init",
		  __LINE__, errno, LOGERROR);
    return NULL;
  }
  
  return e;

}

int pbcext_element_GT_free(pbcext_element_GT_t *e) {

  if (!e) { return IOK; }

  mclBnGT_clear(e);
  mem_free(e);
  e = NULL;
    
  return IOK;

}

int pbcext_element_Fp_clear(pbcext_element_Fp_t *e) {
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_clear", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnFp_clear(e);
  return IOK;

}

int pbcext_element_Fr_clear(pbcext_element_Fr_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_clear", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnFr_clear(e);
  return IOK;

}

int pbcext_element_G1_clear(pbcext_element_G1_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_clear", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnG1_clear(e);
  return IOK;
  
}

int pbcext_element_G2_clear(pbcext_element_G2_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_clear", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnG2_clear(e);
  return IOK;

}


int pbcext_element_GT_clear(pbcext_element_GT_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_clear", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnGT_clear(e);
  return IOK;

}

/* int pbcext_element_init_same_as(pbcext_element_t **dst, pbcext_element_t *src) { */
/*   return IERROR; */
/* } */

int pbcext_element_Fp_set(pbcext_element_Fp_t *dst, pbcext_element_Fp_t *src) {

  byte_t *bytes;
  uint64_t len;
  int rc;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_set", __LINE__, LOGERROR);
    return IERROR; 
  }

  /* @TODO Isn't there a native way to do assignments????? */
  bytes = NULL;
  if (pbcext_element_Fp_to_bytes(&bytes, &len, src) == IERROR) return IERROR;
  rc = pbcext_element_Fp_from_bytes(dst, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;
  
}

int pbcext_element_Fr_set(pbcext_element_Fr_t *dst, pbcext_element_Fr_t *src) {

  byte_t *bytes;
  uint64_t len;
  int rc;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_set", __LINE__, LOGERROR);
    return IERROR; 
  }

  /* @TODO Isn't there a native way to do assignments????? */
  bytes = NULL;
  if (pbcext_element_Fr_to_bytes(&bytes, &len, src) == IERROR) return IERROR;
  rc = pbcext_element_Fr_from_bytes(dst, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;
  
}

int pbcext_element_G1_set(pbcext_element_G1_t *dst, pbcext_element_G1_t *src) {

  byte_t *bytes;
  uint64_t len;
  int rc;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_set", __LINE__, LOGERROR);
    return IERROR; 
  }

  /* @TODO Isn't there a native way to do assignments????? */
  bytes = NULL;
  if (pbcext_element_G1_to_bytes(&bytes, &len, src) == IERROR) return IERROR;
  rc = pbcext_element_G1_from_bytes(dst, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;
  
}

int pbcext_element_G2_set(pbcext_element_G2_t *dst, pbcext_element_G2_t *src) {

  byte_t *bytes;
  uint64_t len;
  int rc;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_set", __LINE__, LOGERROR);
    return IERROR; 
  }

  /* @TODO Isn't there a native way to do assignments????? */
  bytes = NULL;
  if (pbcext_element_G2_to_bytes(&bytes, &len, src) == IERROR) return IERROR;
  rc = pbcext_element_G2_from_bytes(dst, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;
  
}

int pbcext_element_GT_set(pbcext_element_GT_t *dst, pbcext_element_GT_t *src) {

  byte_t *bytes;
  uint64_t len;
  int rc;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_set", __LINE__, LOGERROR);
    return IERROR; 
  }

  /* @TODO Isn't there a native way to do assignments????? */
  bytes = NULL;
  if (pbcext_element_GT_to_bytes(&bytes, &len, src) == IERROR) return IERROR;
  rc = pbcext_element_GT_from_bytes(dst, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;
  
}

/** Arithmetic operations **/

/* Return error code */
int pbcext_element_Fp_random(pbcext_element_Fp_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_random_Fp", __LINE__, LOGERROR);
    return IERROR; 
  }
    
  if(mclBnFp_setByCSPRNG(e)) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_random_Fp",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }


  return IOK;
  
}

int pbcext_element_Fr_random(pbcext_element_Fr_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_random_Fr", __LINE__, LOGERROR);
    return IERROR; 
  }
    
  if(mclBnFr_setByCSPRNG(e)) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_random_Fr",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  return IOK;
  
}

int pbcext_element_G1_random(pbcext_element_G1_t *e) {

  pbcext_element_Fr_t r;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_random_G1", __LINE__, LOGERROR);
    return IERROR; 
  }

  if (pbcext_element_Fr_random(&r) == IERROR) return IERROR;
  if (pbcext_element_G1_mul(e, &G1_GEN, &r) == IERROR) return IERROR;
 
  return IOK;

}

int pbcext_element_G2_random(pbcext_element_G2_t *e) {

  pbcext_element_Fr_t r;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_random_G2", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  if (pbcext_element_Fr_random(&r) == IERROR) return IERROR;
  if (pbcext_element_G2_mul(e, &G2_GEN, &r) == IERROR) return IERROR;
   
  return IOK;

}

int pbcext_element_Fr_add(pbcext_element_Fr_t *dst,
			  pbcext_element_Fr_t *e1,
			  pbcext_element_Fr_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_add", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFr_add(dst, e1, e2);

  return IOK;
  
}

int pbcext_element_Fp_add(pbcext_element_Fp_t *dst,
			  pbcext_element_Fp_t *e1,
			  pbcext_element_Fp_t *e2) {
  
  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_add", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnFp_add(dst, e1, e2);

  return IOK;
  
}

int pbcext_element_G1_add(pbcext_element_G1_t *dst,
			  pbcext_element_G1_t *e1,
			  pbcext_element_G1_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_add", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnG1_add(dst, e1, e2);

  return IOK;
  
}

int pbcext_element_G2_add(pbcext_element_G2_t *dst,
			  pbcext_element_G2_t *e1,
			  pbcext_element_G2_t *e2) {
  
  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_add", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnG2_add(dst, e1, e2);

  return IOK;
  
}

/* GT is a multiplicative group in MCL, so no add/neg/sub */

int pbcext_element_Fr_sub(pbcext_element_Fr_t *dst,
			  pbcext_element_Fr_t *e1,
			  pbcext_element_Fr_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_sub", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFr_sub(dst, e1, e2);

  return IOK;
  
}

int pbcext_element_Fp_sub(pbcext_element_Fp_t *dst,
			  pbcext_element_Fp_t *e1,
			  pbcext_element_Fp_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_sub", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFp_sub(dst, e1, e2);

  return IOK;
  
}

int pbcext_element_G1_sub(pbcext_element_G1_t *dst,
			  pbcext_element_G1_t *e1,
			  pbcext_element_G1_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_sub", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnG1_sub(dst, e1, e2);

  return IOK;
  
}

int pbcext_element_G2_sub(pbcext_element_G2_t *dst,
			  pbcext_element_G2_t *e1,
			  pbcext_element_G2_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_sub", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnG2_sub(dst, e1, e2);

  return IOK;
  
}

int pbcext_element_Fr_neg(pbcext_element_Fr_t *dst, pbcext_element_Fr_t *e) {

  if (!dst || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_neg", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFr_neg(dst, e);
  
  return IOK;

}

int pbcext_element_Fp_neg(pbcext_element_Fp_t *dst, pbcext_element_Fp_t *e) {

  if (!dst || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_neg", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFp_neg(dst, e);
  
  return IOK;

}

int pbcext_element_G1_neg(pbcext_element_G1_t *dst, pbcext_element_G1_t *e) {

  if (!dst || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_neg", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnG1_neg(dst, e);
  
  return IOK;

}

int pbcext_element_G2_neg(pbcext_element_G2_t *dst, pbcext_element_G2_t *e) {

  if (!dst || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_neg", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnG2_neg(dst, e);
  
  return IOK;

}

int pbcext_element_Fr_inv(pbcext_element_Fr_t *dst, pbcext_element_Fr_t *e) {

  if (!dst || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_inv", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFr_inv(dst, e);

  return IOK;

}

int pbcext_element_Fp_inv(pbcext_element_Fp_t *dst, pbcext_element_Fp_t *e) {

  if (!dst || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_inv", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFp_inv(dst, e);

  return IOK;

}

int pbcext_element_GT_inv(pbcext_element_GT_t *dst, pbcext_element_GT_t *e) {

  if (!dst || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_inv", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnGT_inv(dst, e);

  return IOK;

}

int pbcext_element_Fr_mul(pbcext_element_Fr_t *dst,
			  pbcext_element_Fr_t *e1,
			  pbcext_element_Fr_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_mul", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnFr_mul(dst, e1, e2);
  
  return IOK;

}

int pbcext_element_Fp_mul(pbcext_element_Fp_t *dst,
			  pbcext_element_Fp_t *e1,
			  pbcext_element_Fp_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_mul", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnFp_mul(dst, e1, e2);
  
  return IOK;

}

int pbcext_element_GT_mul(pbcext_element_GT_t *dst,
			  pbcext_element_GT_t *e1,
			  pbcext_element_GT_t *e2) {

  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_mul", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnGT_mul(dst, e1, e2);
  
  return IOK;

}

int pbcext_element_Fr_div(pbcext_element_Fr_t *dst,
			  pbcext_element_Fr_t *dividend,
			  pbcext_element_Fr_t *divisor) {

  if (!dst || !dividend || !divisor) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_div", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnFr_div(dst, dividend, divisor);

  return IOK;
  
}

int pbcext_element_Fp_div(pbcext_element_Fp_t *dst,
			  pbcext_element_Fp_t *dividend,
			  pbcext_element_Fp_t *divisor) {

  if (!dst || !dividend || !divisor) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_div", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnFp_div(dst, dividend, divisor);

  return IOK;
  
}

int pbcext_element_GT_div(pbcext_element_GT_t *dst,
			  pbcext_element_GT_t *dividend,
			  pbcext_element_GT_t *divisor) {

  if (!dst || !dividend || !divisor) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_div", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnGT_div(dst, dividend, divisor);

  return IOK;
  
}

int pbcext_element_G1_mul(pbcext_element_G1_t *dst,
			  pbcext_element_G1_t *e,
			  pbcext_element_Fr_t *s) {

  if (!dst || !e || !s) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_mul", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnG1_mul(dst, e, s);
  
  return IOK;
  
}

int pbcext_element_G2_mul(pbcext_element_G2_t *dst,
			  pbcext_element_G2_t *e,
			  pbcext_element_Fr_t *s) {

  if (!dst || !e || !s) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_mul", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnG2_mul(dst, e, s);
  
  return IOK;
    
}

int pbcext_element_GT_pow(pbcext_element_GT_t *dst,
			  pbcext_element_GT_t *base,
			  pbcext_element_Fr_t *exp) {

  if (!dst || !base || !exp) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_pow", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnGT_pow(dst, base, exp);
  
  return IOK;
  
}

int pbcext_pairing(pbcext_element_GT_t *dst,
		   pbcext_element_G1_t *e1,
		   pbcext_element_G2_t *e2) {
  
  if (!dst || !e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_pairing", __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBn_pairing(dst, e1, e2);
  
  return IOK;
  
}

/* Return 0 or 1 */
int pbcext_element_Fr_cmp(pbcext_element_Fr_t *e1, pbcext_element_Fr_t *e2) {

  if (!e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_cmp", __LINE__, LOGERROR);
    return IERROR; 
  }

  return !mclBnFr_isEqual(e1, e2);
  
}

int pbcext_element_Fp_cmp(pbcext_element_Fp_t *e1, pbcext_element_Fp_t *e2) {

  if (!e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_cmp", __LINE__, LOGERROR);
    return IERROR; 
  }

  return !mclBnFp_isEqual(e1, e2);
  
}

int pbcext_element_G1_cmp(pbcext_element_G1_t *e1, pbcext_element_G1_t *e2) {

  if (!e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_cmp", __LINE__, LOGERROR);
    return IERROR; 
  }

  return !mclBnG1_isEqual(e1, e2);
  
}

int pbcext_element_G2_cmp(pbcext_element_G2_t *e1, pbcext_element_G2_t *e2) {

  if (!e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_cmp", __LINE__, LOGERROR);
    return IERROR; 
  }

  return !mclBnG2_isEqual(e1, e2);
  
}

int pbcext_element_GT_cmp(pbcext_element_GT_t *e1, pbcext_element_GT_t *e2) {

  if (!e1 || !e2) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_cmp", __LINE__, LOGERROR);
    return IERROR; 
  }

  return !mclBnGT_isEqual(e1, e2);
  
}

int pbcext_element_Fr_is0(pbcext_element_Fr_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_is0", __LINE__, LOGERROR);
    return IERROR; 
  }

  return mclBnFr_isZero(e);
  
}

int pbcext_element_Fp_is0(pbcext_element_Fp_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_is0", __LINE__, LOGERROR);
    return IERROR; 
  }

  return mclBnFp_isZero(e);
  
}


int pbcext_element_Fr_is1(pbcext_element_Fr_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_is1", __LINE__, LOGERROR);
    return IERROR; 
  }

  return mclBnFr_isOne(e);
  
}

int pbcext_element_Fp_is1(pbcext_element_Fp_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_is1", __LINE__, LOGERROR);
    return IERROR; 
  }

  return mclBnFp_isOne(e);
  
}

int pbcext_element_G1_is0(pbcext_element_G1_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_is0", __LINE__, LOGERROR);
    return IERROR; 
  }

  return mclBnG1_isZero(e);
  
}

int pbcext_element_G2_is0(pbcext_element_G2_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_is0", __LINE__, LOGERROR);
    return IERROR; 
  }
  
  return mclBnG2_isZero(e);
  
}

int pbcext_element_GT_is0(pbcext_element_GT_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_is0", __LINE__, LOGERROR);
    return IERROR; 
  }

  return mclBnGT_isZero(e);
  
}

int pbcext_element_GT_is1(pbcext_element_GT_t *e) {

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_is1", __LINE__, LOGERROR);
    return IERROR; 
  }

  return mclBnGT_isOne(e);
  
}

/** Import/Export **/
int pbcext_element_Fp_byte_size(uint64_t *size) {

  if(!size) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_byte_size",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  *size = mclBn_getFpByteSize();

  return IOK;
  
}

int pbcext_element_Fr_byte_size(uint64_t *size) {

  if(!size) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_byte_size",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  *size = mclBn_getFrByteSize();

  return IOK;
  
}

int pbcext_element_G1_byte_size(uint64_t *size) {

  if(!size) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_byte_size",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  *size = mclBn_getG1ByteSize();

  return IOK;

}

int pbcext_element_G2_byte_size(uint64_t *size) {

  if(!size) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_byte_size",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  *size = mclBn_getG1ByteSize();
  *size *= 2;
  
  return IOK;
  
}

int pbcext_element_GT_byte_size(uint64_t *size) {

  if(!size) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_byte_size",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  *size = mclBn_getFpByteSize();
  *size *= 12;
  
  return IOK;
  
}

int pbcext_element_Fr_to_bytes(byte_t **dst,
			       uint64_t *len,
			       pbcext_element_Fr_t *e) {

  byte_t *bytes;
  uint64_t _len;

  if (!dst || !len || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_to_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if (pbcext_element_Fr_byte_size(&_len) == IERROR) return IERROR;
  if (!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*_len))) return IERROR;

  if (mclBnFr_serialize(bytes, _len, e) != _len) {
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }

  if (!*dst) {
    *dst = bytes;
  } else {
    memcpy(*dst, bytes, _len);
    mem_free(bytes); bytes = NULL;
  }
  
  *len = _len;
  
  return IOK;

}

int pbcext_element_Fp_to_bytes(byte_t **dst,
			       uint64_t *len,
			       pbcext_element_Fp_t *e) {

  byte_t *bytes;
  uint64_t _len;

  if (!dst || !len || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_to_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if (pbcext_element_Fp_byte_size(&_len) == IERROR) return IERROR;
  if (!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*_len))) return IERROR;
  
  if (mclBnFp_serialize(bytes, _len, e) != _len) {
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }

  if (!*dst) {
    *dst = bytes;
  } else {
    memcpy(*dst, bytes, _len);
    mem_free(bytes); bytes = NULL;
  }
    
  *len = _len;
  
  return IOK;

}

int pbcext_element_G1_to_bytes(byte_t **dst,
			       uint64_t *len,
			       pbcext_element_G1_t *e) {

  pbcext_element_G1_t *en;
  byte_t *bytes;
  uint64_t _len, _lenFp;

  if (!dst || !len || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_to_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if (pbcext_element_G1_byte_size(&_len) == IERROR) return IERROR;  
  if (!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*_len))) return IERROR;
  
  if (mclBnG1_serialize(bytes, _len, e) != _len) {
    mem_free(bytes); bytes = NULL;
    return IERROR;
  } 

  if (!*dst) {
    *dst = bytes;
  } else {
    memcpy(*dst, bytes, _len);
    mem_free(bytes); bytes = NULL;
  }
 
  *len = _len;
  
  return IOK;

}

int pbcext_element_G2_to_bytes(byte_t **dst,
			       uint64_t *len,
			       pbcext_element_G2_t *e) {

  byte_t *bytes;
  uint64_t _len;

  if (!dst || !len || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_to_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if (pbcext_element_G2_byte_size(&_len) == IERROR) return IERROR;
  if (!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*_len))) return IERROR;
  
  if (mclBnG2_serialize(bytes, _len, e) != _len) {
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }
  
  if (!*dst) {
    *dst = bytes;
  } else {
    memcpy(*dst, bytes, _len);
    mem_free(bytes); bytes = NULL;
  }

  *len = _len;
  
  return IOK;

}

int pbcext_element_GT_to_bytes(byte_t **dst,
			       uint64_t *len,
			       pbcext_element_GT_t *e) {

  byte_t *bytes;
  uint64_t _len;

  if (!dst || !len || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_to_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if (pbcext_element_GT_byte_size(&_len) == IERROR) return IERROR;
  if (!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*_len))) return IERROR;
  
  if (mclBnGT_serialize(bytes, _len, e) != _len) {
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }

  if (!*dst) {
    *dst = bytes;
  } else {
    memcpy(*dst, bytes, _len);
    mem_free(bytes); bytes = NULL;
  }
    
  *len = _len;
  
  return IOK;

}

int pbcext_element_Fr_from_bytes(pbcext_element_Fr_t *e,
				 byte_t *src,
				 uint64_t len) {

  if (!e || !src || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_from_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if(!mclBnFr_deserialize(e, src, len)) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_Fr_from_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  return IOK;
  
}

int pbcext_element_Fp_from_bytes(pbcext_element_Fp_t *e,
				 byte_t *src,
				 uint64_t len) {

  if (!e || !src || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_from_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if(!mclBnFp_deserialize(e, src, len)) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_Fp_from_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  return IOK;
  
}

int pbcext_element_G1_from_bytes(pbcext_element_G1_t *e,
				 byte_t *src,
				 uint64_t len) {

  if (!e || !src || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_from_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if(mclBnG1_deserialize(e, src, len) != len) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_G1_from_bytes",
  		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  return IOK;
  
}

int pbcext_element_G2_from_bytes(pbcext_element_G2_t *e,
				 byte_t *src,
				 uint64_t len) {

  if (!e || !src || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_from_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if(!mclBnG2_deserialize(e, src, len)) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_G2_from_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  return IOK;
  
}

int pbcext_element_GT_from_bytes(pbcext_element_GT_t *e,
				 byte_t *src,
				 uint64_t len) {

  if (!e || !src || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_from_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if(!mclBnGT_deserialize(e, src, len)) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_GT_from_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  return IOK; 
  
}

int pbcext_element_Fr_from_unformat_bytes(pbcext_element_Fr_t *e,
					  byte_t *src,
					  uint64_t len) {

  if (!e || !src || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_from_unformat_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFr_setLittleEndian(e, src, len);
  
  return IOK;

}

int pbcext_element_Fp_from_unformat_bytes(pbcext_element_Fp_t *e,
					  byte_t *src,
					  uint64_t len) {

  if (!e || !src || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_from_unformat_bytes",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFp_setLittleEndian(e, src, len);
  
  return IOK;

}

int pbcext_element_Fr_from_hash(pbcext_element_Fr_t *dst,
				byte_t *h,
				uint64_t len) {

  if (!dst || !h || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_from_hash",
	       __LINE__, LOGERROR);
    return IERROR; 
  }
  
  mclBnFr_setHashOf(dst, h, len);

  return IOK;
  
}

int pbcext_element_Fp_from_hash(pbcext_element_Fp_t *dst,
				byte_t *h,
				uint64_t len) {

  if (!dst || !h || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_from_hash",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  mclBnFp_setHashOf(dst, h, len);

  return IOK;
  
}

int pbcext_element_G1_from_hash(pbcext_element_G1_t *dst,
				byte_t *h,
				uint64_t len) {

  if (!dst || !h || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_from_hash",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if(mclBnG1_hashAndMapTo(dst, h, len)) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_G1_from_hash",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  return IOK;

}

int pbcext_element_G2_from_hash(pbcext_element_G2_t *dst,
				byte_t *h,
				uint64_t len) {

  if (!dst || !h || !len) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_from_hash",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  if(mclBnG2_hashAndMapTo(dst, h, len)) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_G1_from_hash",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  return IOK;

}

char* pbcext_element_Fr_to_b64(pbcext_element_Fr_t *e) {

  byte_t *bytes;
  char *s;
  uint64_t len;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_to_b64",
	       __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(pbcext_element_Fr_to_bytes(&bytes, &len, e) == IERROR) {
    return NULL;
  }
  
  s = base64_encode(bytes, len, 0);

  /* We do not want the trailing '\n' */
  if (s[strlen(s)-1] == '\n') s[strlen(s)-1] = 0;

  mem_free(bytes); bytes = NULL;

  return s;
  
}

char* pbcext_element_Fp_to_b64(pbcext_element_Fp_t *e) {

  byte_t *bytes;
  char *s;
  uint64_t len;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_to_b64",
	       __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(pbcext_element_Fp_to_bytes(&bytes, &len, e) == IERROR) {
    return NULL;
  }
  
  s = base64_encode(bytes, len, 0);

  /* We do not want the trailing '\n' */
  if (s[strlen(s)-1] == '\n') s[strlen(s)-1] = 0;

  mem_free(bytes); bytes = NULL;
  
  return s;
  
}

char* pbcext_element_G1_to_b64(pbcext_element_G1_t *e) {

  byte_t *bytes;
  char *s;
  uint64_t len;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_to_b64",
	       __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(pbcext_element_G1_to_bytes(&bytes, &len, e) == IERROR) {
    return NULL;
  }
  
  s = base64_encode(bytes, len, 0);

  /* We do not want the trailing '\n' */
  if (s[strlen(s)-1] == '\n') s[strlen(s)-1] = 0;

  mem_free(bytes); bytes = NULL;

  return s;
  
}

char* pbcext_element_G2_to_b64(pbcext_element_G2_t *e) {

  byte_t *bytes;
  char *s;
  uint64_t len;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_to_b64",
	       __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(pbcext_element_G2_to_bytes(&bytes, &len, e) == IERROR) {
    return NULL;
  }
  
  s = base64_encode(bytes, len, 0);

  /* We do not want the trailing '\n' */
  if (s[strlen(s)-1] == '\n') s[strlen(s)-1] = 0;

  mem_free(bytes); bytes = NULL;

  return s;
  
}

char* pbcext_element_GT_to_b64(pbcext_element_GT_t *e) {

  byte_t *bytes;
  char *s;
  uint64_t len;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_to_b64",
	       __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(pbcext_element_GT_to_bytes(&bytes, &len, e) == IERROR) {
    return NULL;
  }
  
  s = base64_encode(bytes, len, 0);

  /* We do not want the trailing '\n' */
  if (s[strlen(s)-1] == '\n') s[strlen(s)-1] = 0;

  mem_free(bytes); bytes = NULL;

  return s;
  
}

int pbcext_element_Fr_from_b64(pbcext_element_Fr_t *e, char *b64) {

  byte_t *bytes;
  uint64_t len;
  int rc;

  if(!e || !b64) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_from_b64",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the Base64 string */
  if(!(bytes = base64_decode(b64, &len))) {
    return IERROR;
  }

  /* Get the element from the byte representation */
  rc = pbcext_element_Fr_from_bytes(e, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;

}

int pbcext_element_Fp_from_b64(pbcext_element_Fp_t *e, char *b64) {

  byte_t *bytes;
  uint64_t len;
  int rc;

  if(!b64) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fp_from_b64",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the Base64 string */
  if(!(bytes = base64_decode(b64, &len))) {
    return IERROR;
  }

  /* Get the element from the byte representation */
  rc = pbcext_element_Fp_from_bytes(e, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;

}

int pbcext_element_G1_from_b64(pbcext_element_G1_t *e, char *b64) {

  byte_t *bytes;
  uint64_t len;
  int rc;

  if(!b64) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_from_b64",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the Base64 string */
  if(!(bytes = base64_decode(b64, &len))) {
    return IERROR;
  }

  /* Get the element from the byte representation */
  rc = pbcext_element_G1_from_bytes(e, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;

}

int pbcext_element_G2_from_b64(pbcext_element_G2_t *e, char *b64) {

  byte_t *bytes;
  uint64_t len;
  int rc;

  if(!b64) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_from_b64",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the Base64 string */
  if(!(bytes = base64_decode(b64, &len))) {
    return IERROR;
  }

  /* Get the element from the byte representation */
  rc = pbcext_element_G2_from_bytes(e, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;

}

int pbcext_element_GT_from_b64(pbcext_element_GT_t *e, char *b64) {

  byte_t *bytes;
  uint64_t len;
  int rc;

  if(!b64) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_from_b64",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the Base64 string */
  if(!(bytes = base64_decode(b64, &len))) {
    return IERROR;
  }

  /* Get the element from the byte representation */
  rc = pbcext_element_GT_from_bytes(e, bytes, len);
  mem_free(bytes); bytes = NULL;

  return rc;

}

int pbcext_dump_element_Fr_fd(pbcext_element_Fr_t *e, FILE *fd) {
  
  byte_t *bytes;
  uint64_t len64;
  int len;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_Fr_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the element */
  bytes = NULL;
  if(pbcext_element_Fr_to_bytes(&bytes, &len64, e) == IERROR) {
    return IERROR;
  }

  len = (int) len64;

  /* Dump size of the element, in bytes */
  if(fwrite(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_Fr_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Dump the actual element */
  if(fwrite(bytes, len, 1, fd)  != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_Fr_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  mem_free(bytes); bytes = NULL;

  return IOK;

}

int pbcext_dump_element_Fp_fd(pbcext_element_Fp_t *e, FILE *fd) {
  
  byte_t *bytes;
  uint64_t len64;
  int len;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_Fp_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the element */
  bytes = NULL;
  if(pbcext_element_Fp_to_bytes(&bytes, &len64, e) == IERROR) {
    return IERROR;
  }
  
  /* Dump size of the element, in bytes */
  len = (int) len64;
  if(fwrite(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_Fp_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Dump the actual element */
  if(fwrite(bytes, len, 1, fd)  != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_Fp_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  mem_free(bytes); bytes = NULL;

  return IOK;

}

int pbcext_dump_element_G1_fd(pbcext_element_G1_t *e, FILE *fd) {
  
  byte_t *bytes;
  uint64_t len64;
  int len;

  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_G1_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the element */
  bytes = NULL;
  if(pbcext_element_G1_to_bytes(&bytes, &len64, e) == IERROR) {
    return IERROR;
  }

  /* Dump size of the element, in bytes */
  len = (int) len64;
  if(fwrite(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_G1_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Dump the actual element */
  if(fwrite(bytes, len, 1, fd)  != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_G1_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  mem_free(bytes); bytes = NULL;

  return IOK;

}

int pbcext_dump_element_G2_fd(pbcext_element_G2_t *e, FILE *fd) {
  
  byte_t *bytes;
  uint64_t len64;
  int len;
  
  if (!e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_G2_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the byte representation of the element */
  bytes = NULL;
  if(pbcext_element_G2_to_bytes(&bytes, &len64, e) == IERROR) {
    return IERROR;
  }
  
  /* Dump size of the element, in bytes */
  len = (int) len64;  
  if(fwrite(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_G2_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Dump the actual element */
  if(fwrite(bytes, len, 1, fd)  != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_G2_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  mem_free(bytes); bytes = NULL;

  return IOK;

}

/* int pbcext_dump_element_GT_fd(pbcext_element_GT_t *e, FILE *fd) { */
  
/*   byte_t bytes[MAX_GT_SIZE_STR+1]; */
/*   int len; */
  
/*   if (!e) { */
/*     LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_GT_fd", */
/* 	       __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   /\* Get the byte representation of the element *\/ */
/*   memset(bytes, 0, MAX_GT_SIZE_STR+1); */
/*   if(pbcext_element_GT_to_bytes(bytes, &len, e) == IERROR) { */
/*     return IERROR; */
/*   } */
  
/*   /\* Dump size of the element, in bytes *\/ */
/*   if(fwrite(&len, sizeof(int), 1, fd) != 1) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_GT_fd", */
/* 		  __LINE__, errno, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   /\* Dump the actual element *\/ */
/*   if(fwrite(bytes, len, 1, fd)  != 1) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_GT_fd", */
/* 		  __LINE__, errno, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   return IOK; */

/* } */

int pbcext_dump_element_Fr_bytes(byte_t **bytes,
				 uint64_t *written,
				 pbcext_element_Fr_t *e) {

  byte_t *_bytes, *__bytes;
  uint64_t len64;
  int len;

  if(!bytes || !written || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_Fr_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

   /* Get the byte representation of the element */
  _bytes = NULL;
  if(pbcext_element_Fr_to_bytes(&_bytes, &len64, e) == IERROR) {
    return IERROR;
  }

  __bytes = (byte_t *) mem_malloc(sizeof(byte_t)*(len64+sizeof(int)));
  if(!__bytes) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }

  /* Dump size of the element, in bytes */
  len = (int) len64;  
  if(!(memcpy(__bytes, &len, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_Fr_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
    
  /* Dump the element */
  memcpy(&__bytes[sizeof(int)], _bytes, len);
  
  if (!*bytes) *bytes = __bytes;
  else {
    memcpy(*bytes, __bytes, len+sizeof(int));
    mem_free(__bytes); __bytes = NULL;
  }

  *written = sizeof(int)+len;
  mem_free(_bytes); _bytes = NULL;

  return IOK;

}

int pbcext_dump_element_Fp_bytes(byte_t **bytes,
				 uint64_t *written,
				 pbcext_element_Fp_t *e) {

  byte_t *_bytes, *__bytes;
  uint64_t len64;
  int len;

  if(!bytes || !written || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_Fp_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

   /* Get the byte representation of the element */
  _bytes = NULL;
  if(pbcext_element_Fp_to_bytes(&_bytes, &len64, e) == IERROR) {
    return IERROR;
  }

  __bytes = (byte_t *) mem_malloc(sizeof(byte_t)*(len64+sizeof(int)));
  if(!__bytes) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }

  /* Dump size of the element, in bytes */
  len = (int) len64;  
  if(!(memcpy(__bytes, &len, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_Fp_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
    
  /* Dump the element */
  memcpy(&__bytes[sizeof(int)], _bytes, len);
  
  if (!*bytes) *bytes = __bytes;
  else {
    memcpy(*bytes, __bytes, len+sizeof(int));
    mem_free(__bytes); __bytes = NULL;
  }

  *written = sizeof(int)+len;
  mem_free(_bytes); _bytes = NULL;

  return IOK;

}

int pbcext_dump_element_G1_bytes(byte_t **bytes,
				 uint64_t *written,
				 pbcext_element_G1_t *e) {

  byte_t *_bytes, *__bytes;
  uint64_t len64;
  int len;

  if(!bytes || !written || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_G1_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

   /* Get the byte representation of the element */
  _bytes = NULL;
  if(pbcext_element_G1_to_bytes(&_bytes, &len64, e) == IERROR) {
    return IERROR;
  }

  __bytes = (byte_t *) mem_malloc(sizeof(byte_t)*(len64+sizeof(int)));
  if(!__bytes) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }

  /* Dump size of the element, in bytes */
  len = (int) len64;  
  if(!(memcpy(__bytes, &len, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_G1_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
    
  /* Dump the element */
  memcpy(&__bytes[sizeof(int)], _bytes, len);
  
  if (!*bytes) *bytes = __bytes;
  else {
    memcpy(*bytes, __bytes, len+sizeof(int));
    mem_free(__bytes); __bytes = NULL;
  }

  *written = sizeof(int)+len;
  mem_free(_bytes); _bytes = NULL;

  return IOK;

}

int pbcext_dump_element_G2_bytes(byte_t **bytes,
				 uint64_t *written,
				 pbcext_element_G2_t *e) {

  byte_t *_bytes, *__bytes;
  uint64_t len64;
  int len;

  if(!bytes || !written || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_G2_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

   /* Get the byte representation of the element */
  _bytes = NULL;
  if(pbcext_element_G2_to_bytes(&_bytes, &len64, e) == IERROR) {
    return IERROR;
  }

  __bytes = (byte_t *) mem_malloc(sizeof(byte_t)*(len64+sizeof(int)));
  if(!__bytes) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }

  /* Dump size of the element, in bytes */
  len = (int) len64;  
  if(!(memcpy(__bytes, &len, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_G2_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
    
  /* Dump the element */
  memcpy(&__bytes[sizeof(int)], _bytes, len);
  
  if (!*bytes) *bytes = __bytes;
  else {
    memcpy(*bytes, __bytes, len+sizeof(int));
    mem_free(__bytes); __bytes = NULL;
  }

  *written = sizeof(int)+len;
  mem_free(_bytes); _bytes = NULL;

  return IOK;

}

int pbcext_dump_element_GT_bytes(byte_t **bytes,
				 uint64_t *written,
				 pbcext_element_GT_t *e) {

  byte_t *_bytes, *__bytes;
  uint64_t len64;
  int len;

  if(!bytes || !written || !e) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_dump_element_GT_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

   /* Get the byte representation of the element */
  _bytes = NULL;
  if(pbcext_element_GT_to_bytes(&_bytes, &len64, e) == IERROR) {
    return IERROR;
  }

  __bytes = (byte_t *) mem_malloc(sizeof(byte_t)*(len64+sizeof(int)));
  if(!__bytes) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }

  /* Dump size of the element, in bytes */
  len = (int) len64;  
  if(!(memcpy(__bytes, &len, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_dump_element_GT_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
    
  /* Dump the element */
  memcpy(&__bytes[sizeof(int)], _bytes, len);
  
  if (!*bytes) *bytes = __bytes;
  else {
    memcpy(*bytes, __bytes, len+sizeof(int));
    mem_free(__bytes); __bytes = NULL;
  }

  *written = sizeof(int)+len;
  mem_free(_bytes); _bytes = NULL;

  return IOK;

}

int pbcext_get_element_Fr_fd(pbcext_element_Fr_t *e, bool *read, FILE *fd) {

  byte_t *bytes;
  uint64_t len64;
  int len;

  if(!e || !read || !fd) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_Fr_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Read the number of bytes of the element */
  if(fread(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fr_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = false; return IOK; }

  /* Read the element bytes */
  if(!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*len))) {
    return IERROR;
  }

  memset(bytes, 0, len);
  if(fread(bytes, len, 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fr_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }
  
  /* Import the element */
  len64 = (uint64_t) len;
  if(pbcext_element_Fr_from_bytes(e, bytes, len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fr_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;    
  }

  *read = true;
  
  mem_free(bytes); bytes = NULL;

  return IOK;

}

int pbcext_get_element_Fp_fd(pbcext_element_Fp_t *e, bool *read, FILE *fd) {

  byte_t *bytes;
  uint64_t len64;  
  int len;

  if(!e || !read || !fd) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_Fp_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Read the number of bytes of the element */
  if(fread(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fp_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = false; return IOK; }

  /* Read the element bytes */
  if(!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*len))) {
    return IERROR;
  }

  memset(bytes, 0, len);
  if(fread(bytes, len, 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fp_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }
  
  /* Import the element */
  len64 = (uint64_t) len;
  if(pbcext_element_Fp_from_bytes(e, bytes, len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fp_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;    
  }

  *read = true;
  mem_free(bytes); bytes = NULL;

  return IOK;

}

int pbcext_get_element_G1_fd(pbcext_element_G1_t *e, bool *read, FILE *fd) {

  byte_t *bytes;
  uint64_t len64;  
  int len;

  if(!e || !read || !fd) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_G1_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Read the number of bytes of the element */
  if(fread(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G1_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = false; return IOK; }

  /* Read the element bytes */
  if(!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*len))) {
    return IERROR;
  }

  memset(bytes, 0, len);
  if(fread(bytes, len, 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G1_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }

  /* Import the element */
  len64 = (uint64_t) len;
  if(pbcext_element_G1_from_bytes(e, bytes, len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G1_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;    
  }

  *read = true;
  mem_free(bytes); bytes = NULL;

  return IOK;

}

int pbcext_get_element_G2_fd(pbcext_element_G2_t *e, bool *read, FILE *fd) {

  byte_t *bytes;
  uint64_t len64;
  int len;

  if(!e || !read || !fd) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_G2_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Read the number of bytes of the element */
  if(fread(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G2_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = false; return IOK; }

  /* Read the element bytes */
  if(!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*len))) {
    return IERROR;
  }

  memset(bytes, 0, len);
  if(fread(bytes, len, 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G2_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }
  
  /* Import the element */
  len64 = (uint64_t) len;
  if(pbcext_element_G2_from_bytes(e, bytes, len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G2_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;    
  }

  *read = true;
  mem_free(bytes); bytes = NULL;

  return IOK;

}

int pbcext_get_element_GT_fd(pbcext_element_GT_t *e, bool *read, FILE *fd) {

  byte_t *bytes;
  uint64_t len64;
  int len;

  if(!e || !read || !fd) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_GT_fd",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Read the number of bytes of the element */
  if(fread(&len, sizeof(int), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_GT_fd",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = false; return IOK; }

  /* Read the element bytes */
  if(!(bytes = (byte_t *) mem_malloc(sizeof(byte_t)*len))) {
    return IERROR;
  }

  memset(bytes, 0, len);
  if(fread(bytes, len, 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_GT_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }
  
  /* Import the element */
  len64 = (uint64_t) len;
  if(pbcext_element_GT_from_bytes(e, bytes, len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_GT_fd",
		  __LINE__, errno, LOGERROR);
    mem_free(bytes); bytes = NULL;
    return IERROR;    
  }

  *read = true;
  mem_free(bytes); bytes = NULL;

  return IOK;

}

int pbcext_get_element_Fr_bytes(pbcext_element_Fr_t *e,
				uint64_t *read,
				byte_t *bytes) {

  uint64_t len64;
  int len;

  if(!e || !read || !bytes) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_Fr_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(memcpy(&len, bytes, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fr_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  *read = sizeof(int);

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = 0; return IOK; }

  len64 = (uint64_t) len;
  if(pbcext_element_Fr_from_bytes(e, &bytes[*read], len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fr_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;    
  }

  *read += len;

  return IOK;

}

int pbcext_get_element_Fp_bytes(pbcext_element_Fp_t *e,
				uint64_t *read,
				byte_t *bytes) {

  uint64_t len64;
  int len;

  if(!e || !read || !bytes) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_Fp_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(memcpy(&len, bytes, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fp_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  *read = sizeof(int);  

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = 0; return IOK; }

  len64 = (uint64_t) len;
  if(pbcext_element_Fp_from_bytes(e, &bytes[*read], len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_Fp_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;    
  }

  *read += len;

  return IOK;

}

int pbcext_get_element_G1_bytes(pbcext_element_G1_t *e,
				uint64_t *read,
				byte_t *bytes) {

  uint64_t len64;
  int len;

  if(!e || !read || !bytes) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_G1_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(memcpy(&len, bytes, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G1_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  *read = sizeof(int);

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = 0; return IOK; }

  len64 = (uint64_t) len;
  if(pbcext_element_G1_from_bytes(e, &bytes[*read], len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G1_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;    
  }

  *read += len;

  return IOK;

}

int pbcext_get_element_G2_bytes(pbcext_element_G2_t *e,
				uint64_t *read,
				byte_t *bytes) {

  uint64_t len64;
  int len;

  if(!e || !read || !bytes) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_G2_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(memcpy(&len, bytes, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G2_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  *read = sizeof(int);

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = 0; return IOK; }

  len64 = (uint64_t) len;
  if(pbcext_element_G2_from_bytes(e, &bytes[*read], len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_G2_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;    
  }

  *read += len;

  return IOK;

}

int pbcext_get_element_GT_bytes(pbcext_element_GT_t *e,
				uint64_t *read,
				byte_t *bytes) {

  uint64_t len64;
  int len;

  if(!e || !read || !bytes) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_get_element_GT_bytes",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(memcpy(&len, bytes, sizeof(int)))) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_GT_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  *read = sizeof(int);

  /* Check len is not 0; this may not be an error, just an indicator of an 
     empty field. */
  if (!len) { *read = 0; return IOK; }
  
  len64 = (uint64_t) len;
  if(pbcext_element_GT_from_bytes(e, &bytes[*read], len64) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "pbcext_get_element_GT_bytes",
		  __LINE__, errno, LOGERROR);
    return IERROR;    
  }

  *read += len;

  return IOK;

}

int pbcext_element_Fr_to_string(char **str,
				uint64_t *len,
				int base,
				pbcext_element_Fr_t *e) {

  if(!str || !e || (base != 10 && base != 16)) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_to_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }
  
  if(!(*str)) {

    if(!(*str = mem_malloc(sizeof(char) * 1024))) {
      return IERROR;
    }
    
    if(!mclBnFr_getStr(*str, 1024, e, base)) {
      LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_Fr_to_string",
  		    __LINE__, ENOLINK, LOGERROR);
      return IERROR;
    }
    
    *len = strlen(*str);

  } else {
    
    mclBnFr_getStr(*str, *len, e, base);

  }

  return IOK;

}

int pbcext_element_G1_to_string(char **str,
				uint64_t *len,
				int base,
				pbcext_element_G1_t *e) {

  if(!str || !e || (base != 10 && base != 16)) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_to_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }
	 
  if(!(*str)) {

    if(!(*str = mem_malloc(sizeof(char) * 1024))) {
      return IERROR;
    }

    if(!mclBnG1_getStr(*str, 1024, e, base)) {
      LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_G1_to_string",
		    __LINE__, ENOLINK, LOGERROR);
      return IERROR;
    }

    *len = strlen(*str);

  } else {
    
    mclBnG1_getStr(*str, *len, e, base);

  }

  return IOK;

}

int pbcext_element_G2_to_string(char **str,
				uint64_t *len,
				int base,
				pbcext_element_G2_t *e) {

  if(!str || !e || (base != 10 && base != 16)) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_to_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }
	 
  if(!(*str)) {

    if(!(*str = mem_malloc(sizeof(char) * 2048))) {
      return IERROR;
    }

    if(!mclBnG2_getStr(*str, 2048, e, base)) {
      LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_G2_to_string",
		    __LINE__, ENOLINK, LOGERROR);
      return IERROR;
    }

    *len = strlen(*str);

  } else {
    
    mclBnG2_getStr(*str, *len, e, base);

  }

  return IOK;

}

int pbcext_element_GT_to_string(char **str,
				uint64_t *len,
				int base,
				pbcext_element_GT_t *e) {

  if(!str || !e || (base != 10 && base != 16)) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_to_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }
	 
  if(!(*str)) {

    if(!(*str = mem_malloc(sizeof(char) * 2048))) {
      return IERROR;
    }

    if(!mclBnGT_getStr(*str, 2048, e, base)) {
      LOG_ERRORCODE(&logger, __FILE__, "pbcext_element_GT_to_string",
		    __LINE__, ENOLINK, LOGERROR);
      return IERROR;
    }

    *len = strlen(*str);

  } else {
    
    mclBnGT_getStr(*str, *len, e, base);

  }

  return IOK;

}

int pbcext_element_Fr_from_string(pbcext_element_Fr_t **e,
				  char *str,
				  int base) {

  pbcext_element_Fr_t *_e;
  
  if (!e || !str || (base != 10 && base != 16)) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_Fr_from_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if (!(_e = pbcext_element_Fr_init()))
    return IERROR;

  if (mclBnFr_setStr(_e, (const char *) str, strlen(str), base) == -1) {
    pbcext_element_Fr_free(_e); _e = NULL;
    return IERROR;
  }

  if (!e) *e = _e;
  else {
    if (pbcext_element_Fr_set(*e, _e) == IERROR) {
      pbcext_element_Fr_free(_e); _e = NULL;
      return IERROR;    
    }
    pbcext_element_Fr_free(_e); _e = NULL;    
  }

  return IOK;
  
}

int pbcext_element_G1_from_string(pbcext_element_G1_t **e,
				  char *str,
				  int base) {

  pbcext_element_G1_t *_e;
  
  if (!e || !str || (base != 10 && base != 16)) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G1_from_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if (!(_e = pbcext_element_G1_init()))
    return IERROR;

  if (mclBnG1_setStr(_e, (const char *) str, strlen(str), base) == -1) {
    pbcext_element_G1_free(_e); _e = NULL;
    return IERROR;
  }

  if (!e) *e = _e;
  else {
    if (pbcext_element_G1_set(*e, _e) == IERROR) {
      pbcext_element_G1_free(_e); _e = NULL;
      return IERROR;    
    }
    pbcext_element_G1_free(_e); _e = NULL;    
  }

  return IOK;
  
}

int pbcext_element_G2_from_string(pbcext_element_G2_t **e,
				  char *str,
				  int base) {

  pbcext_element_G2_t *_e;
  
  if (!e || !str || (base != 10 && base != 16)) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_G2_from_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if (!(_e = pbcext_element_G2_init()))
    return IERROR;

  if (mclBnG2_setStr(_e, (const char *) str, strlen(str), base) == -1) {
    pbcext_element_G2_free(_e); _e = NULL;
    return IERROR;
  }

  if (!e) *e = _e;
  else {
    if (pbcext_element_G2_set(*e, _e) == IERROR) {
      pbcext_element_G2_free(_e); _e = NULL;
      return IERROR;    
    }
    pbcext_element_G2_free(_e); _e = NULL;    
  }

  return IOK;
  
}

int pbcext_element_GT_from_string(pbcext_element_GT_t **e,
				  char *str,
				  int base) {

  pbcext_element_GT_t *_e;
  
  if (!e || !str || (base != 10 && base != 16)) {
    LOG_EINVAL(&logger, __FILE__, "pbcext_element_GT_from_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if (!(_e = pbcext_element_GT_init()))
    return IERROR;

  if (mclBnGT_setStr(_e, (const char *) str, strlen(str), base) == -1) {
    pbcext_element_GT_free(_e); _e = NULL;
    return IERROR;
  }

  if (!e) *e = _e;
  else {
    if (pbcext_element_GT_set(*e, _e) == IERROR) {
      pbcext_element_GT_free(_e); _e = NULL;
      return IERROR;    
    }
    pbcext_element_GT_free(_e); _e = NULL;    
  }

  return IOK;
  
}

/* pbc_ext.c ends here */
