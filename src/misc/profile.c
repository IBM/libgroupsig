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

double _profile_timeval_to_double(struct timeval *tv){
  double wtime = 0;
  char walltime[21] = {0};
  sprintf(walltime, "%lu.%06d", tv->tv_sec, tv->tv_usec);
  sscanf(walltime, "%lf", &wtime);
  return wtime;
}

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

int profile_dump_entry(profile_t *prof,
		       struct timeval *tvbegin, struct timeval *tvend,
		       clock_t clckbegin, clock_t clckend,
		       uint64_t cyclebegin, uint64_t cycleend) {

  FILE *fd;
  double cpustart = (double) clckbegin / (double) CLOCKS_PER_SEC;
  double cpuend = (double) clckend / (double) CLOCKS_PER_SEC;
  double wallstart = _profile_timeval_to_double(tvbegin);
  double wallend = _profile_timeval_to_double(tvend);

  if(!prof) {
    LOG_EINVAL(&logger, __FILE__, "profile_dump_entry", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Dump the new entry to the file */
  if(!(fd = fopen(prof->filename, "a"))) {
    LOG_ERRORCODE(&logger, __FILE__, "profile_dump_entry", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  fprintf(fd, entry_fmt_string,
      tvbegin->tv_sec, tvbegin->tv_usec,
      tvend->tv_sec, tvend->tv_usec,
      wallend - wallstart,
      cpustart, cpuend, cpuend - cpustart,
      cyclebegin, cycleend, cycleend - cyclebegin);

  fclose(fd); fd = NULL;

  /* Add the new entry to the file (errors ignored) */
  profile_add_entry(prof, tvbegin, tvend, clckbegin, clckend, cyclebegin, cycleend);
  prof->printed++;

  return IOK;
  
}

int profile_dump_data(profile_t *prof) {

  FILE *fd;
  uint64_t i;
  double cpustart;
  double cpuend;
  double wallstart;
  double wallend;

  if(!prof) {
    LOG_EINVAL(&logger, __FILE__, "profile_dump_data", __LINE__, LOGERROR);
    return IERROR;
  }
  
  if(!(fd = fopen(prof->filename, "a"))) {
    LOG_ERRORCODE(&logger, __FILE__, "profile_dump_data", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  for(i=0; i<prof->n; i++) {
    cpustart = (double) prof->entries[i].clckbegin / (double) CLOCKS_PER_SEC;
    cpuend = (double) prof->entries[i].clckend / (double) CLOCKS_PER_SEC;
    wallstart = _profile_timeval_to_double(&prof->entries[i].tvbegin);
    wallend = _profile_timeval_to_double(&prof->entries[i].tvend);
    fprintf(fd, entry_fmt_string,
	    prof->entries[i].tvbegin.tv_sec,
	    prof->entries[i].tvbegin.tv_usec,
	    prof->entries[i].tvend.tv_sec,
	    prof->entries[i].tvend.tv_usec,
	    prof->entries[i].cyclebegin,
	    prof->entries[i].cycleend,
	    wallend - wallstart,
	    cpustart, cpuend, cpuend - cpustart);
    prof->printed++;
  }
  fclose(fd); fd = NULL;

  return IOK;
  
}

/* profile.c ends here */
