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
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <time.h>

#include "sysenv.h"
#include "mem.h"

static int _sysenv_seed(sysenv_t *sysenv, unsigned int seed) {

  unsigned int s;
  /* long int r; */
  int attempts, rc;

  if (!sysenv) {
    LOG_EINVAL(&logger, __FILE__, "_sysenv_seed", __LINE__, LOGERROR);
    return IERROR;    
  }

  rc = IOK;
  
#if HAVE_GETRANDOM
  /* If on Linux or Mac, call sys_getrandom, which draws a cryptographically 
     secure random number from the OS only after it has been fully 
     initialized. */
  rc = sysenv_getrandom(&s, sizeof(unsigned int));

#else
  /* Fall back to srandom(), @TODO look for ways of seeding it that minimize 
     the badness of this... */
  // @TODO Maybe fallback to Openssl -- since it is already a dependency...
  // Explore in issue14
  if (seed != UINT_MAX) srandom(seed);
  else srandom(time(NULL));

  /* /\* Random returns a long int and bigz_randseed_ui wants an unsigned int; just */
  /*    cast to an unsigned int *\/ */
  /* r = random(); */
  /* s = (unsigned int) r; */

#endif

  /* /\* Initialize big numbers random *\/ */
  /* bigz_randinit_default(sysenv->big_rand); */
  /* bigz_randseed_ui(sysenv->big_rand, s);   */

  return rc;
  
}

sysenv_t* sysenv_init(unsigned int seed) {

  sysenv_t *sysenv;

  if(!(sysenv = (sysenv_t *) mem_malloc(sizeof(sysenv_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "sysenv_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  memset(sysenv, 0, sizeof(sysenv_t));
  if(!(sysenv->big_ctx = BN_CTX_new())) {
    LOG_ERRORCODE(&logger, __FILE__, "sysenv_init", __LINE__, errno, LOGERROR);
    mem_free(sysenv); sysenv = NULL;
    return NULL;      
  }
  sysenv->data = NULL;

  if (_sysenv_seed(sysenv, seed) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "sysenv_init", __LINE__, errno, LOGERROR);
    mem_free(sysenv); sysenv = NULL;
    return NULL;  
  }
  
  return sysenv;

}

int sysenv_free(sysenv_t *sysenv) {

  if(!sysenv) {
    LOG_EINVAL_MSG(&logger, __FILE__, "sysenv_free", __LINE__,  
		   "Nothing to free.", LOGERROR); 
    return IOK;
  }

  /* bigz_randclear(sysenv->big_rand); */
  BN_CTX_free(sysenv->big_ctx);
  sysenv->big_ctx = NULL;

  free(sysenv);

  return IOK;

}

int sysenv_getrandom(void *buf, int size) {

  unsigned int s;
  int attempts, rc;

  if (!buf || size <= 0) {
    LOG_EINVAL(&logger, __FILE__, "sysenv_getrandom", __LINE__, LOGERROR);
    return IERROR;
  }
  
#if defined(HAVE_GETRANDOM) && defined (__linux__)
  
  /* Should check kernel version supports getrandom() */

  /* Use getrandom() */

  /* Call getrandom to make sure /dev/urandom is correctly initialized. */
  attempts = 0; rc = 0;
  while (attempts < MAX_GETRANDOM_ATTEMPTS) {
    errno = 0;
    if ((rc = getrandom(buf, size, 0)) != -1) break;
    attempts++;
  }

  /* rc will be -1 if, after MAX_GETRANDOM_ATTEMPTS, getrandom has still 
     not succeeded. */
  if (rc == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "sysenv_getrandom", __LINE__, 
		  errno, LOGERROR);    
    return IERROR;
  }
  
#elif defined(HAVE_GETRANDOM) && defined (__APPLE__)
  /* Use arc4random() */
  arc4random_buf(buf, size);
#else
  /* Fall back to random(), which must have been seeded in sysenv_init */
  // @TODO Check that sysenv has been initialized!
  // @TODO Maybe fallback to OpenSSL? Explore in issue14
  int fetched;
  long int r;

  /* Copy the random data into buf until we have all the requested data */
  fetched = 0;
  while (fetched < size) {
    r = random();
    memcpy(buf + fetched, &r, sizeof(long int));
    fetched += sizeof(long int);
  }
  
#endif

  return IOK;

}

/* int sysenv_reseed(unsigned int seed) { */

/*   bigz_randclear(sysenv->big_rand); */
/*   return _sysenv_seed(seed); */

/* } */

/* sysenv.c ends here */
