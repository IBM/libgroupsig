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
#include "bigf.h"
#include "bigz.h"
#include "logger.h"

bigf_t bigf_init() {

  bigf_t bf;

  if(!(bf = (bigf_t) malloc(sizeof(mpf_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bigf_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  return bf;

}

bigf_t bigf_init_set(bigf_t op) {

  bigf_t bf;

  if(!op) {
    LOG_EINVAL(&logger, __FILE__, "bigf_init_set", __LINE__, LOGERROR);
    return NULL;    
  }

  if(!(bf = bigf_init())) {
    return NULL;
  }

  mpf_init_set(*bf, *op);
  
  return bf;

}

/* bigz_t bigz_init_set_ui(unsigned long int op) { */

/*   bigz_t bz; */

/*   if(!op) { */
/*     LOG_EINVAL(&logger, __FILE__, "bigz_init_set_ui", __LINE__, LOGERROR); */
/*     return IERROR;     */
/*   } */

/*   if(!(bz = big_zinit())) { */
/*     return NULL; */
/*   } */

/*   mpz_init_set_ui(*bz, op); */
  
/*   return bz; */

/* } */

int bigf_free(bigf_t op) {
  
  /* If there is nothing to free, ok, but throw warning... */
  if(!op) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bigf_free", __LINE__, EINVAL, 
		      "Nothing to free.", LOGWARN);
    return IERROR;
  }
  
  mpf_clear(*op);
  free(op); 
  op = NULL;
  
  return IOK;

}

int bigf_set_prec(bigf_t rop, unsigned long int prec) {

  if(!rop) {
    LOG_EINVAL(&logger, __FILE__, "bigf_set_prec", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_set_prec(*rop, prec);
  
  return IOK;

}

int bigf_set(bigf_t rop, bigf_t op) {

  if(!rop || !op) {
    LOG_EINVAL(&logger, __FILE__, "bigf_set", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_set(*rop, *op);

  return IOK;

}

int bigf_set_z(bigf_t n, bigz_t z_n) {

  if(!n || !z_n) {
    LOG_EINVAL(&logger, __FILE__, "bigf_set_z", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_set_z(*n, *z_n);
  
  return IOK;

}

int bigf_set_ui(bigf_t rop, unsigned long int op) {

  if(!rop) {
    LOG_EINVAL(&logger, __FILE__, "bigf_set_ui", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_set_ui(*rop, op);
  
  return IOK;

}

int bigf_add(bigf_t rop, bigf_t op1, bigf_t op2) {

  if(!rop || !op1 || !op2) {
    LOG_EINVAL(&logger, __FILE__, "bigf_add", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_add(*rop, *op1, *op2);

  return IOK;

}

int bigf_add_ui(bigf_t rop, bigf_t op1, unsigned long int op2) {

  if(!rop || !op1) {
    LOG_EINVAL(&logger, __FILE__, "bigf_add_ui", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_add_ui(*rop, *op1, op2);

  return IOK;

}

int bigf_mul(bigf_t rop, bigf_t op1, bigf_t op2) {

  if(!rop || !op1 || !op2) {
    LOG_EINVAL(&logger, __FILE__, "bigf_mul", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_mul(*rop, *op1, *op2);
  
  return IOK;

}

int bigf_div(bigf_t rop, bigf_t op1, bigf_t op2) {

  if(!rop || !op1 || !op2) {
    LOG_EINVAL(&logger, __FILE__, "bigf_div", __LINE__, LOGERROR);
    return IERROR;
  }

  errno = 0;
  if(!bigf_cmp_ui(op2, 0) && !errno) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bigf_div", __LINE__,
		   "Division by zero.", LOGERROR);
    return IERROR;
  }

  mpf_div(*rop, *op1, *op2);

  return IOK;

}

int bigf_div_ui(bigf_t rop, bigf_t op1, unsigned long int op2) {

  if(!rop || !op1) {
    LOG_EINVAL(&logger, __FILE__, "bigf_div_ui", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!op2) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bigf_div_ui", __LINE__, 
		   "Division by zero.", LOGERROR);
    return IERROR;
  }

  mpf_div_ui(*rop, *op1, op2);

  return IOK;

}

int bigf_div_2exp(bigf_t rop, bigf_t op1, unsigned long int op2) {

  if(!rop || !op1) {
    LOG_EINVAL(&logger, __FILE__, "bigf_div_2exp", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_div_2exp(*rop, *op1, op2);

  return IOK;

}

int bigf_cmp_ui(bigf_t op1, unsigned long int op2) {

  if(!op1) {
    LOG_EINVAL(&logger, __FILE__, "bigf_cmp_ui", __LINE__, LOGERROR);
    return IERROR;
  }

  return mpf_cmp_ui(*op1, op2);
  
}

int bigf_floor(bigf_t rop, bigf_t n) {
  
  if(!rop || !n) {
    LOG_EINVAL(&logger, __FILE__, "bigf_floor", __LINE__, LOGERROR);
    return IERROR;
  }

  mpf_floor(*rop, *n);

  return IOK;

}

int bigf_log2(bigf_t log2n, bigf_t n, uint64_t precission) {
  
  bigf_t y, _log2n, aux;
  bigz_t z;
  size_t size2;
  uint64_t m;
  int rc;

  if(!precission) {
    bigf_set_ui(log2n, 0);
    return IOK;
  }

  /* Based on the algorithm in http://en.wikipedia.org/wiki/Binary_logarithm */

  /* 1) Compute the integer part */
  if(!(aux = bigf_init())) {
    return IERROR;
  }

  if(bigf_floor(aux, n) == IERROR) {
    bigf_free(aux);
    return IERROR;
  }

  if(!(z = bigz_init())) {
    bigf_free(aux);
    return IERROR;
  }

  if(bigz_set_f(z, aux) == IERROR) {
    bigf_free(aux); bigz_free(z);
    return IERROR;
  }

  errno = 0;
  size2 = bigz_sizeinbase(z, 2);
  if(errno) {
    bigf_free(aux); bigz_free(z);
    return IERROR;    
  }

  bigz_free(z);

  if(!(_log2n = bigf_init())) {
    bigf_free(aux);
    return IERROR;    
  }
  
  if(bigf_add_ui(_log2n, _log2n, size2-1) == IERROR) {
    bigf_free(aux); bigf_free(_log2n);
    return IERROR;
  }

  if(!(y = bigf_init_set(n))) {
    bigf_free(aux); bigf_free(_log2n);
    return IERROR;    
  }
  
  if(bigf_div_2exp(y, y, size2-1) == IERROR) {
    bigf_free(aux); bigf_free(_log2n); bigf_free(y);
    return IERROR;
  }

  /* if y == 1, then we have a exact logarithm */
  errno = 0; rc = IOK;
  if(!bigf_cmp_ui(y, 1)) {

    if(errno || bigf_set(log2n, _log2n) == IERROR) {
      rc = IERROR;
    }

    bigf_free(aux); bigf_free(y); bigf_free(_log2n);

    return rc;

  }

  /* 2) If not, y is in [1,2) and we have to get the fractional part */
 
  /* 2.1) Square y repeatedly until the result belongs to [2,4) */
  m = 0; errno = 0;
  do {
    if(errno || bigf_mul(y, y, y) == IERROR) {
      bigf_free(aux); bigf_free(y); bigf_free(_log2n);
      return IERROR;
    }
    m++;
    errno = 0;
  } while(bigf_cmp_ui(y, 2) < 0);
  
  /* y/2 is again a number in [1,2), and log2(y) = 2^(-m)+2^(-m)*log2(y/2),
     but now we can use the log function of the math library to avoid recursion. */
  if(bigf_div_ui(y, y, 2) == IERROR) {
    bigf_free(aux); bigf_free(y); bigf_free(_log2n);
    return IERROR;
  }
  if(bigf_log2(aux, y, precission-1) == IERROR) { /** @todo Remove recursion! */
    bigf_free(aux); bigf_free(y); bigf_free(_log2n);
    return IERROR;
  }
  
  if(bigf_div_2exp(aux, aux, m) == IERROR) {
    bigf_free(aux); bigf_free(y); bigf_free(_log2n);
    return IERROR;
  }

  if(bigf_add(_log2n, _log2n, aux) == IERROR) {
    bigf_free(aux); bigf_free(y); bigf_free(_log2n);
    return IERROR;
  }
  
  if(bigf_set_ui(aux, 1) == IERROR) {
    bigf_free(aux); bigf_free(y); bigf_free(_log2n);
    return IERROR;    
  }

  if(bigf_div_2exp(aux, aux, m) == IERROR) {
    bigf_free(aux); bigf_free(y); bigf_free(_log2n);
    return IERROR;
  }

  if(bigf_add(_log2n, _log2n, aux) == IERROR) {
    bigf_free(aux); bigf_free(y); bigf_free(_log2n);
    return IERROR;
  }

  if(bigf_set(log2n, _log2n) == IERROR) {
    bigf_free(aux); bigf_free(y); bigf_free(_log2n);
    return IERROR;
  }
  
  bigf_free(_log2n);
  bigf_free(aux);
  bigf_free(y);

  return IOK;
  
}



/* bigf.c ends here */
