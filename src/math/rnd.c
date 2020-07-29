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

#include "sysenv.h"
#include "rnd.h"
#include "logger.h"

uint64_t rnd_get_random_int_in_range(uint64_t n) {

  int attempts, rc;
  uint64_t r;
  
  if (n < 0) {
    LOG_EINVAL(&logger, __FILE__, "rnd_get_random_int_in_range",
	       __LINE__, LOGERROR);
    return -1;
  }

  /* Call sysenv_getrandom, which uses the best available randomness source. */
  if (sysenv_getrandom(&r, sizeof(uint64_t)) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "rnd_get_random_int_in_range", __LINE__, 
		  errno, LOGERROR);    
    return -1;
  }  

  return r % (n+1);

}

/* rnd.c ends here */
