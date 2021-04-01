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

#include "profile.h"
#include "types.h"
#include "logger.h"
#include "sys/mem.h"
#include "groupsig.h"

#include <stdio.h>
#include <sys/time.h>
#include <math.h>

//Print the following values, tab delimited:
// Wall Start Seconds (secs.usec)
// Wall End Seconds (secs.usec)
// Wall Clock Difference (End - Start)
// CPU Clock Start (float seconds)
// CPU Clock End (float seconds)
// CPU Clock Difference (End - Start)
// CPU Cycle Start (cycles)
// CPU Cycle End (cycles)
// CPU Cycle Difference (End - Start)
static const char* entry_fmt_string = "%lu.%06lu\t%lu.%06lu\t%.6f\t%.6f\t%.6f\t%.6f\t%u\t%u\t%u\n";

#ifdef __i386
__inline__ uint64_t rdtsc() {
  uint64_t x;
  __asm__ volatile ("rdtsc" : "=A" (x));
  return x;
}
#elif __amd64
__inline__ uint64_t rdtsc() {
  uint64_t a, d;
  __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
  return (d<<32) | a;
}
#endif

profile_t* profile_begin(char *filename) {

  profile_t *profile;

  if(!filename) {
    LOG_EINVAL(&logger, __FILE__, "profile_begin", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(profile = mem_malloc(sizeof(profile_t)))) {
    return NULL;
  }
  
  if(!(profile->filename = strdup(filename))) {
    LOG_ERRORCODE(&logger, __FILE__, "profile_begin", __LINE__, errno, LOGERROR);
    mem_free(profile); profile = NULL;
    return NULL;
  }
  profile->entries = NULL;
  profile->n = 0;
  profile->printed = 0;

  return profile;

}

int profile_free(profile_t *profile) {

  if(!profile) {
    LOG_EINVAL_MSG(&logger, __FILE__, "profile_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(profile->filename) { mem_free(profile->filename); profile->filename = NULL; }

  if(profile->entries) {
    mem_free(profile->entries); profile->entries = NULL;
  }

  mem_free(profile); profile = NULL;

  return IOK;

}

int profile_get_time(struct timeval *tv, clock_t *clck, uint64_t *cycle) {

  if(!tv) {
    LOG_EINVAL(&logger, __FILE__, "profile_get_time", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get current time */
  if(gettimeofday(tv, NULL) == -1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "profile_get_time", __LINE__,
  		      errno, "Failed to get current time.", LOGERROR);
    return IERROR;
  }

  if((*clck = clock()) == (clock_t) -1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "profile_get_time", __LINE__,
		      errno, "Failed to get clock time.", LOGERROR);
    return IERROR;
  }

  /* Get current clock cycle */
  *cycle = rdtsc();

  return IOK;

}

int profile_add_entry(profile_t *profile, struct timeval *tvbegin, struct timeval *tvend, 
		      clock_t clckbegin, clock_t clckend,
		      uint64_t cyclebegin, uint64_t cycleend) {

  uint64_t n;

  if(!profile || !tvbegin || !tvend) {
    LOG_EINVAL(&logger, __FILE__, "profile_add_entry", __LINE__, LOGERROR);
    return IERROR;
  }

  n = profile->n;

  if(!(profile->entries = (profile_entry_t *) 
       mem_realloc(profile->entries, sizeof(profile_entry_t)*(n+1)))) {
    return IERROR;
  }

  profile->n++;

  profile->entries[n].tvbegin.tv_sec = tvbegin->tv_sec;
  profile->entries[n].tvbegin.tv_usec = tvbegin->tv_usec;
  profile->entries[n].tvend.tv_sec = tvend->tv_sec;
  profile->entries[n].tvend.tv_usec = tvend->tv_usec;
  profile->entries[n].clckbegin = clckbegin;
  profile->entries[n].clckend = clckend;
  profile->entries[n].cyclebegin = cyclebegin;
  profile->entries[n].cycleend = cycleend;

  return IOK;

}

int profile_process_and_dump(profile_t *prof, int code, char *operation) {

  double tv_avg, tv_std, clck_avg, clck_std, cycle_avg, cycle_std, delta;
  uint64_t i;
  FILE *fd;
  
  if (!prof || !operation) {
    LOG_EINVAL(&logger, __FILE__, "profile_process_and_dump",
		  __LINE__, LOGERROR);
    return IERROR;
  }

  tv_avg = tv_std = 0.f;
  clck_avg = clck_std = 0.f;
  cycle_avg = cycle_std = 0.f;

  /* Compute average */
  for (i=0; i<prof->n; i++) {
    tv_avg += (
	       (prof->entries[i].tvend.tv_sec*1000000+prof->entries[i].tvend.tv_usec)
	       -
	       (prof->entries[i].tvbegin.tv_sec*1000000+prof->entries[i].tvbegin.tv_usec)
	       );
    clck_avg += (prof->entries[i].clckend - prof->entries[i].clckbegin);
    cycle_avg += (prof->entries[i].cycleend - prof->entries[i].cyclebegin);
  }
  tv_avg = tv_avg / prof->n;
  clck_avg = clck_avg / prof->n;
  cycle_avg = cycle_avg / prof->n;

  /* Compute standard deviation */
  for (i=0; i<prof->n; i++) {
    delta = (prof->entries[i].tvend.tv_sec*1000000+prof->entries[i].tvend.tv_usec) -
      (prof->entries[i].tvbegin.tv_sec*1000000+prof->entries[i].tvbegin.tv_usec);
    tv_std += (delta - tv_avg)*(delta - tv_avg);
    delta = prof->entries[i].clckend - prof->entries[i].clckbegin;
    clck_std += (delta - clck_avg)*(delta - clck_avg);
    delta = prof->entries[i].clckend - prof->entries[i].clckbegin;
    cycle_std += (delta - cycle_avg)*(delta - cycle_avg);
    
  }
  tv_std = sqrt(tv_std / prof->n);
  clck_std = sqrt(clck_std / prof->n);
  cycle_std = sqrt(cycle_std / prof->n);

  fd = fopen(prof->filename, "a");
  if (!fd) {
    LOG_ERRORCODE(&logger, __FILE__, "profile_process_and_dump",
		  errno, __LINE__, LOGERROR);    
    return IERROR;
  }
  
  fprintf(fd,
	  "%s\t%s\t%.6f\t%.6f\t%.6f\t%.6f\n",
	  groupsig_get_name_from_code(code),
	  operation,
	  tv_avg,
	  tv_std,
	  clck_avg,
	  clck_std);

  fclose(fd); fd = NULL;
  
  return IOK;
  
}

/* profile.c ends here */
