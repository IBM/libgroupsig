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

#ifndef _PROFILE_H
#define _PROFILE_H

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

typedef struct {
  struct timeval tvbegin;
  struct timeval tvend;
  clock_t clckbegin;
  clock_t clckend;
  uint64_t cyclebegin;
  uint64_t cycleend;
} profile_entry_t;

typedef struct {
  char *filename;
  profile_entry_t *entries;
  uint64_t n;
  uint64_t printed;
} profile_t;

uint64_t rdtsc();
profile_t* profile_begin(char *filename);
int profile_free(profile_t *profile);
int profile_get_time(struct timeval *tv, clock_t *clck, uint64_t *cycle);
int profile_add_entry(profile_t *profile, struct timeval *tvbegin, struct timeval *tvend, 
		      clock_t clckbegin, clock_t clckend, uint64_t cyclebegin, uint64_t cycleend);

/*
  Utility function: given the entries in prof, computes their average and 
  standard deviation, and appends to the file specified in prof, a line with 
  format: 
  <code>\t<operation>\t<avg of user time>\t<std dev of user time>\t<avg of cpu time>\t<std dev of cpu time>\n
*/
int profile_process_and_dump(profile_t *prof, int code, char *operation);

#endif

/* profile.h ends here */
