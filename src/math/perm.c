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

#include "perm.h"
#include "rnd.h"
#include "logger.h"

int perm_durstenfeld_inplace(void **array, int size) {

  void *tmp;
  uint64_t i, j;

  if (!array || size <= 0) {
    LOG_EINVAL(&logger, __FILE__, "perm_durstenfeld_inplace",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  for (i=size-1; i>0; i--) {

    /* j random integer in [0,i] */
    if(rnd_get_random_int_in_range(&j, i) == IERROR) {
      LOG_ERRORCODE(&logger, __FILE__, "perm_durstenfeld_inplace", __LINE__, 
		    errno, LOGERROR);
      return IERROR;
    }

    /* Swap array[i] and array[j] */
    tmp = array[i];
    array[i] = array[j];
    array[j] = tmp;
    
  }

  return IOK;

}

/* perm.c ends here */
