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
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <fenv.h>
#include <math.h>

#include "types.h"
#include "misc.h"
#include "logger.h"
#include "sys/mem.h"

/* Internal constants: mainly for dirty solutions */
#define MAX_SDOUBLE 100
#define MAX_SUINT32 100
#define MAX_SUINT64 100
#define DEFAULT_BSTRING_LEN 128

int misc_get_fd_size(FILE* fd){
  int file_n = -1;
  size_t size = 0;
  long int old_offset = 0;
  file_n = fileno(fd);
  if(file_n > 2){
    struct stat f_stat;
    fstat(file_n, &f_stat);
    size = f_stat.st_size;
  } else {
    old_offset = ftell(fd);
    errno = 0;
    // SEEK_END isn't portable, so we do this
    while(fseek(fd, size, SEEK_SET) == 0){
      size++;
      if(errno) return -1;
    }
    // The last size failed, so we subtract one
    size--;
    fseek(fd, old_offset, SEEK_SET);
    fflush(fd);
  }
  return size;
}

int misc_read_file_line(FILE *fd, char **line) {

  uint64_t i, line_len;
  char *_line, c;
  uint8_t newline;
  
  if(!line) {
    LOG_EINVAL(&logger, __FILE__, "misc_read_file_line", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Read chars until we see one that is a space (\r,\n,\t,\v) and it is not 
     a blank (\t, ' ') */
  line_len = 200;
  if(!(_line = (char *) malloc(sizeof(char)*line_len))) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_line", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }
  memset(_line, 0, line_len);

  newline = 0; i = 0; c = 0;
  while(!newline) {

    /* See if we have to incrase the size of the line */
    if(i >= line_len) {
      if(!(_line = (char *) realloc(_line, sizeof(char)*line_len*2))) {
	LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_line", __LINE__, 
		      errno, LOGERROR);
	return IERROR;
      }
      memset(&_line[i], 0, line_len*2-line_len);
      line_len *= 2;
    }

    if(fread(&c, 1, 1, fd) < 1) {
      /* If we have reached the EOF, end successfully, otherwise, error */
      if(feof(fd)) {
	break;
      } else {
	free(_line); _line = NULL;
	LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_line", __LINE__, 
		      errno, LOGERROR);
	return IERROR;
      }
    }

    /* No error nor EOF: we've read something, see if it is a new line */
    if(isspace(c) && !isblank(c)) {
      newline = 1; /** @todo Note that this will produce a desynchronization when
		       a new line is marked with "\r\n", since it will read the 
		       '\r' and mark new line without reading \n, which will be 
		       read in the next call, as if it were a different line */
    } else {
      _line[i] = c;
      i++;
    }

  }

  /* If *line == NULL, allocate memory for it, otherwise, copy _line into it */
  if(!*line) {

    /* reallocate _line to have exact size */
    if(!(_line = (char *) realloc(_line, sizeof(char)*(i+1)))) {
	LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_line", __LINE__, 
		      errno, LOGERROR);
	return IERROR;
    }
    
    /* Make *line point to it */
    *line = _line;
  } else {
    memcpy(*line, _line, i);
    free(_line); _line = NULL;
  }

  return IOK;
  
}

int misc_read_file_word(int fd, char **word) {

  char *line;
  ssize_t rd;
  off_t offset, begin, line_len;
  uint8_t eol;

  if(!fd || !word) {
    LOG_EINVAL(&logger, __FILE__, "misc_read_file_word", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Set the initial length of the line to  */
  line_len = MISC_DEFAULT_LINE_LENGTH+1;
  if(!(line = (char *) malloc(sizeof(char)*line_len))) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_word", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  memset(line, 0, line_len);

  eol = 0;
  offset = 0;

  /* Get current position */
  if((begin = lseek(fd, 0, SEEK_CUR)) == (off_t) -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_word", __LINE__, 
		  errno, LOGERROR);
    free(line); line = NULL;
    return IERROR;    
  }

  while(!eol) {

    /* If the line is not long enough, increase its memory */
    if(offset+MISC_DEFAULT_LINE_LENGTH >= line_len) {
      line_len += MISC_DEFAULT_LINE_LENGTH;
      if(!(line = (char *) realloc(line, sizeof(char)*line_len))) {
	LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_word", __LINE__, 
		      errno, LOGERROR);
	return IERROR;
      }
      memset(&line[offset], 0, MISC_DEFAULT_LINE_LENGTH);
    }

    /* Read MISC_DEFAULT_LINE_LENGTH bytes */
    if((rd = read(fd, &line[offset], MISC_DEFAULT_LINE_LENGTH-1)) == -1) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_word", __LINE__, 
		    errno, LOGERROR);
      free(line); line = NULL;
      return IERROR;
    }

    /* If we read 0 bytes, but we have not yet reached an EOL, error */
    if(!rd) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_word", __LINE__, 
		    EBADF, LOGERROR);
      free(line); line = NULL;
      return IERROR;
    }

    /* Inspect if any of the read bytes is a blank or a space */
    for(offset=0; offset<rd; offset++) {
      if(isspace(line[offset]) || isblank(line[offset])) {	
	eol = 1;
	break;
      }
    }

  }

  /* Reposition the file descriptor at the end of the read word */
  if(lseek(fd, begin+offset+1, SEEK_SET) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_word", __LINE__, 
		  errno, LOGERROR);
    free(line); line = NULL;
  }

  /* Fit the length of the read word */
  if(!(line = (char *) realloc(line, sizeof(char)*offset+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_word", __LINE__, 
		  errno, LOGERROR);
    free(line); line = NULL;
    return IERROR;
  }

  line[offset] = 0;

  /* Prepare output */
  if(!*word) {
    *word = line; 
  } else {
    strcpy(*word, line);
  }

  return IOK;

}

int misc_read_bstring_until(byte_t *string, uint64_t s_len, byte_t *delimiter, uint32_t d_len, 
			    byte_t **output, uint64_t *read, uint8_t *finish) {

  byte_t *aux_output=NULL;
  uint64_t i, b_len;

  if(!string || !s_len || !delimiter || d_len <= 0 || !output || !read || !finish) {
    LOG_EINVAL(&logger, __FILE__, "misc_read_bstring_until", __LINE__, LOGERROR);
    return IERROR;
  }

  /* We allocate memory initially for DEFAULT_BSTRING_LEN bytes */
  b_len = DEFAULT_BSTRING_LEN+1;
  if(!(aux_output = (byte_t *) malloc(sizeof(byte_t)*b_len))) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_bstring_until", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }
  memset(aux_output, 0, b_len);

  i = 0;

  /* Iterate the delimiter is found */
  while(s_len >= (d_len + i) &&
	memcmp(&string[i], delimiter, d_len) &&
	memcmp(&string[i], "EOS", 3)) { /** @todo This EOS method is temporary  */
    
    /* If aux_output is not long enough, double its size and reallocate... */
    if(i >= b_len) {

      b_len *= 2;
      if(!(aux_output = realloc((byte_t *) aux_output, b_len))) {
	LOG_ERRORCODE(&logger, __FILE__, "misc_read_bstring_until", __LINE__, 
		      errno, LOGERROR);
	if(aux_output) free(aux_output);
	return IERROR;
      }
      
    }
    
    aux_output[i] = string[i];
    i++;

  }

  /* If d_len + i > s_len, we have not found the delimiter */
  if(d_len + i > s_len) {
    if(aux_output) free(aux_output);
    return IERROR;
  }

  /* Reallocate aux_output to the precise size */
  if(i) {
    if(!(aux_output = realloc((byte_t *) aux_output, i))) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_read_bstring_until", __LINE__, 
		    errno, LOGERROR);
      if(aux_output) free(aux_output);
      return IERROR;
    }

    /* Prepare the output */
    if(*output) {
      memcpy(output, aux_output, i);
      free(aux_output);
    } else {
      *output = aux_output;
    }
  } else {
    free(aux_output); aux_output = NULL;
  }

  *read = i;

  if(!memcmp(&string[i], "EOS", 3)) { /** @todo This EOS method is temporary */
    *finish = 0;
  } else {
    *finish = 1;
  }

  return IOK;

}

int misc_read_file_to_bytestring(char *filename, byte_t **bytestring, 
				 uint64_t *b_len) {

  struct stat buf;
  ssize_t filesize, rc;
  int fd;
  byte_t *bs;

  if(!filename || !bytestring || !b_len) {
    LOG_EINVAL(&logger, __FILE__, "misc_read_file_to_bytestring", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Open the file */
  if((fd = open(filename, O_RDONLY)) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_bytestring", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  /* Get the size of the file */
  if(fstat(fd, &buf) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_bytestring", __LINE__, 
		  errno, LOGERROR);
    close(fd);
    return IERROR;
  }

  filesize = buf.st_size;

  /* If *bytestring is NULL allocate memory internally */
  if(!*bytestring) {
  
    /* Allocate the auxiliar bytestring */
    if(!(bs = (byte_t *) malloc(sizeof(byte_t)*filesize+1))) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_bytestring", __LINE__, 
		    errno, LOGERROR);
      close(fd);
      return IERROR;
    }

    memset(bs, 0, filesize+1);

  } else {
    bs = *bytestring;
  }

  /* Read the data into bs */  
  if((rc = read(fd, bs, filesize)) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_bytestring", __LINE__, 
		  errno, LOGERROR);
    free(bs); bs = NULL;
    close(fd);
    return IERROR;
  }

  close(fd);

  /* Check that we have read everything */
  if(rc != filesize) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_bytestring", __LINE__, 
		  errno, LOGERROR);
    free(bs); bs = NULL;
    return IERROR;
  }

  /* Prepare the output */
  if(!*bytestring) {
    *bytestring = bs;
  }

  *b_len = rc;
  
  return IOK;

}

int misc_read_fd_to_bytestring(FILE *fd, byte_t **bytestring, 
			       uint64_t *b_len) {

  struct stat buf;  
  ssize_t size;
  long pos;
  int fn;
  byte_t *bs;

  if(!fd || !bytestring || !b_len) {
    LOG_EINVAL(&logger, __FILE__, "misc_read_fd_to_bytestring", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the size of the file */
  if((fn = fileno(fd)) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_fd_to_bytestring", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  if(fstat(fn, &buf) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_fd_to_bytestring", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  /* Get the current position of the file descriptor */
  if((pos = ftell(fd)) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_fd_to_bytestring", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  size = buf.st_size - pos;

  /* If *bytestring is NULL allocate memory internally */
  if(!*bytestring) {

    /* Allocate the auxiliar bytestring */
    if(!(bs = (byte_t *) malloc(sizeof(byte_t)*size+1))) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_read_fd_to_bytestring", __LINE__, 
		    errno, LOGERROR);
      return IERROR;
    }

    memset(bs, 0, size+1);

  } else {
    bs = *bytestring;
  }

  /* Read the data (starting from the current position of fd) into bs */  
  if(fread(bs, size, 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_fd_to_bytestring", __LINE__,
		  errno, LOGERROR);
    if(!*bytestring) { mem_free(bs); bs = NULL; }
    return IERROR;
  }
  
  if(ferror(fd)) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_fd_to_bytestring", __LINE__,
		  errno, LOGERROR);
    if(!*bytestring) { mem_free(bs); bs = NULL; }
    return IERROR;
  }

  /* Prepare the output */
  if(!*bytestring) {
    *bytestring = bs;
  }

  *b_len = size;

  /* Reset the position of the file descriptor */
  if(fseek(fd, pos, SEEK_SET) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_fd_to_bytestring", __LINE__,
		  errno, LOGERROR);
    if(!*bytestring) { mem_free(bs); bs = NULL; }
    return IERROR;
  }
  
  return IOK;

}

int misc_read_file_to_string(char *filename, char **bytestring, 
			     uint64_t *b_len) {

  struct stat buf;
  ssize_t filesize, rc;
  FILE *fd;
  char *bs;

  if(!filename || !bytestring || !b_len) {
    LOG_EINVAL(&logger, __FILE__, "misc_read_file_to_string", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Open the file */
  if(!(fd = fopen(filename, "r"))) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_string", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  /* Get the size of the file */
  if(stat(filename, &buf) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_string", __LINE__, 
		  errno, LOGERROR);
    fclose(fd); fd = NULL;
    return IERROR;
  }

  filesize = buf.st_size;

  /* If *bytestring is NULL allocate memory internally */
  if(!*bytestring) {
  
    /* Allocate the auxiliar bytestring */
    if(!(bs = (char *) malloc(sizeof(char)*filesize+1))) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_string", __LINE__, 
		    errno, LOGERROR);
      fclose(fd); fd = NULL;
      return IERROR;
    }

    memset(bs, 0, filesize+1);

  } else {
    bs = *bytestring;
  }

  /* Read the data into bs */  
  if((rc = fread(bs, 1, filesize, fd)) != filesize) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_string", __LINE__, 
		  errno, LOGERROR);
    free(bs); bs = NULL;
    fclose(fd); fd = NULL;
    return IERROR;
  }

  fclose(fd); fd = NULL;

  /* Check that we have read everything */
  if(rc != filesize) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_read_file_to_string", __LINE__, 
		  errno, LOGERROR);
    free(bs); bs = NULL;
    return IERROR;
  }

  /* Prepare the output */
  if(!*bytestring) {
    *bytestring = bs;
  }

  *b_len = rc;
  
  return IOK;

}

int misc_fprintf_bytestring(FILE *fd, byte_t *bytestring, uint64_t b_len) {

  uint64_t i;

  if(!fd || !bytestring) {
    LOG_EINVAL(&logger, __FILE__, "misc_fprintf_bytestring", __LINE__, LOGERROR);
    return IERROR;
  }

  for(i=0; i<b_len; i++) {
    fprintf(fd, "%02X", bytestring[i]);
  }
  
  return IOK;

}

int misc_bytes_to_file(char *filename, byte_t *bytes, uint64_t b_len) {

  FILE *fd;
  ssize_t size;
  
  if (!filename || !bytes || !b_len) {
    LOG_EINVAL(&logger, __FILE__, "misc_bytes_to_file", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(fd = fopen(filename, "w"))) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_bytes_to_file", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  if((size = fwrite(bytes, b_len, 1, fd)) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "misc_bytes_to_file", __LINE__, errno,
		      "Error writing to file", LOGERROR);
    fclose(fd); fd = NULL;
    return IERROR;
  }

  fclose(fd); fd = NULL;
  return IOK;
  
}

char* misc_int2string(int d) {

  char *sd;
  uint32_t sd_len;
  int rc;

  sd = NULL; sd_len = INT_MAX;
  rc = INT_MAX;
  while(rc >= sd_len) {

    if(!(sd = (char *) realloc((char *)sd, sizeof(char)*sd_len))) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_int2string", __LINE__, 
		    errno, LOGERROR);
      return NULL;
    }
    memset(sd, 0, sizeof(char)*sd_len);
    
    if((rc = snprintf(sd, sd_len, "%d", d)) < 0) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_int2string", __LINE__, 
		    errno, LOGERROR);
      free(sd); sd = NULL;
      return NULL;
    }

    if(rc >= sd_len)  {
      sd_len*=2;
      rc = INT_MAX;
    }

  }

  return sd;
  

}

char* misc_uint322string(uint32_t d) {

  char *su;
  uint32_t su_len;
  int rc;

  su = NULL; su_len = MAX_SUINT32;
  rc = INT_MAX;
  while(rc >= su_len) {

    if(!(su = (char *) realloc((char *)su, sizeof(char)*su_len))) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_uint322string", __LINE__, 
		    errno, LOGERROR);
      return NULL;
    }
    memset(su, 0, sizeof(char)*su_len);
    
    if((rc = snprintf(su, su_len, "%u", d)) < 0) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_uint322string", __LINE__, 
		    errno, LOGERROR);
      free(su); su = NULL;
      return NULL;
    }

    if(rc >= su_len)  {
      su_len*=2;
      rc = INT_MAX;
    }

  }

  return su;
  
}

char* misc_uint642string(uint64_t u) {

  double d;
  int di;
  char *str;

  if(u) {
    d = floor(log10(u))+1;
    
    /* Most likely won't happen */
    if (d > INT_MAX) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "uint64_to_string", __LINE__, errno,
			"Too big.", LOGERROR);
      return NULL;
    }

    di = (int) d;
  } else {
    di = 1;
  }

  /* Allocate space for the string */
  if(!(str = mem_malloc(sizeof(char)*(di+1)))) {
    return NULL;
  }
  
  if(sprintf(str, "%llu", u) != di) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "uint64_to_string", __LINE__, errno,
		      "Wrong number of written bytes.", LOGERROR);
    mem_free(str); str = NULL;
    return NULL;
  }
  
  return str;
  
}

char* misc_double2string(double d, const char* format) {

  char *sd;
  uint32_t sd_len;
  int rc;

  if(!format) {
    LOG_EINVAL(&logger, __FILE__, "misc_double2string", __LINE__, LOGERROR);
    return NULL;
  }

  /* Get a string representation of nu */
  sd = NULL; sd_len = MAX_SDOUBLE;
  rc = INT_MAX;
  while(rc >= sd_len) {

    if(!(sd = (char *) realloc((char *)sd, sizeof(char)*sd_len))) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_double2string", __LINE__, 
		    errno, LOGERROR);
      return NULL;
    }
    memset(sd, 0, sizeof(char)*sd_len);
    
    /* Careful! This conversion may lead to inconsistencies... */
    if((rc = snprintf(sd, sd_len, format, d)) < 0) {
      LOG_ERRORCODE(&logger, __FILE__, "misc_double2string", __LINE__, 
		    errno, LOGERROR);
      free(sd); sd = NULL;
      return NULL;
    }

    if(rc >= sd_len)  {
      sd_len*=2;
      rc = INT_MAX;
    }

  }

  return sd;

}

int misc_wait_random_or_enter(time_t max_sec, uint8_t print) {

  struct timespec ts;

  ts.tv_sec = (time_t) (((double) max_sec)*rand()/(RAND_MAX+1.0));
  ts.tv_nsec = (long) (((double) 1000000000)*rand()/(RAND_MAX+1.0));

  if(print) {
    fprintf(stdout, "Sleeping %ld.%ld seconds\n", ts.tv_sec, ts.tv_nsec);
  } 

  if(nanosleep(&ts, NULL) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_wait_random_or_enter", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  return IOK;    

}

int misc_get_hex_representation(char **hex, byte_t *bytes, unsigned long len) {

  char *hexbytes;
  unsigned long i, hex_len;

  if(!hex || !bytes || !len) {
    LOG_EINVAL(&logger, __FILE__, "misc_get_hex_representation", __LINE__, LOGERROR);
    return IERROR;
  }

  hexbytes = NULL;
  
  /* For each byte, we need two characters */
  hex_len = 2*len;
  if(!(hexbytes = (char *) malloc((sizeof(char)*hex_len)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "misc_get_hex_representation", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }
  memset(hexbytes, 0, hex_len+1);

  for(i=0; i<len; i++) {
    if(bytes[i] <= 0xF) sprintf(&hexbytes[2*i], "0%x", bytes[i]);
    else sprintf(&hexbytes[2*i], "%x", bytes[i]);
  }

  *hex = hexbytes;
  
  return IOK;

}

int misc_fprintf_tabulated(FILE *stream, uint8_t tabs, uint32_t linelen, char *string) {

  int i, j, len;

  if(!string || !linelen) {
    LOG_EINVAL(&logger, __FILE__, "misc_fprintf_tabulated", __LINE__, LOGERROR);
    return IERROR;
  }

  len = strlen(string);

  for(i=0; i<len; i++) {
    
    /* Print '\n' and 'tabs' tabs if we have already printed 80 chars since the 
       last tabs */
    if(!(i%linelen)) {
      fprintf(stream, "\n");
      for(j=0; j<tabs; j++) {
	fprintf(stream, "\t");
      }
    }
    
    fprintf(stream, "%c", string[i]);

  }

  return IOK;

}

/* misc.c ends here */
