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

#ifndef _RND_H
#define _RND_H

#include "types.h"

/** 
 * @fn int random_get_random_int_in_range(uint64_t *r, uint64_t n)
 * @brief Returns a random integer in the interval [0,n]. The system's
 *  random number generator must have been initialized with a call to srand
 *  before calling this function. (This can be done by calling groupsig_init.)
 *
 * @param[in,out] r Pointer to uint64_t to store the produced number.
 * @param[in] n The upper limit of the interval.
 * 
 * @return IOK or IERROR.
 */
int rnd_get_random_int_in_range(uint64_t *r, uint64_t n);

#endif

/* rnd.h ends here */
