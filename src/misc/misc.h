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

#ifndef _MISC_H
#define _MISC_H

#include "types.h"
#include <time.h>

/**
 * @def MISC_EOF
 * @brief Flag to indicate that EOF has been found while parsing a file.
 */
#define MISC_EOF 127

/**
 * @def MISC_DEFAULT_LINE_LENGTH
 * @brief Sets the default line length to use when parsing a file.
 */
#define MISC_DEFAULT_LINE_LENGTH 100

/**
 * @def MISC_DEFAULT_NMEMB
 * @brief Sets the default number of bytes to read from a file when calling fread.
 */
#define MISC_DEFAULT_NMEMB 50

/**
 * @def MISC_DELAY_MAX
 * @brief Sets the maximum delay to three seconds for actions that require random waits.
 */
#define MISC_DELAY_MAX 3

/**
 * @fn int misc_get_fd_size(FILE* fd)
 * @brief Returns the size of the file in <i>fd</>, in bytes.
 * 
 * @param[in,out] fd The file descriptor.
 * 
 * @return The size of fd, in bytes, or -1 if error.
 */
int misc_get_fd_size(FILE* fd);

/** 
 * @fn int misc_read_file_line(FILE *fd, char **line)
 * @brief Reads a line from the given file descriptor. The trailing \n is
 *  not included in the resulting string.
 *
 * @param[in] fd The file descriptor.
 * @param[in,out] line Will store the read line. If *line is NULL, memory will
 *  be allocated internally, otherwise, it must be big enough to store the result.
 * 
 * @return IOK or IERROR
 */
int misc_read_file_line(FILE *fd, char **line);

/** 
 * @fn int misc_read_file_word(int fd, char **word)
 * @brief Reads from the given file descriptor until a blank or a space is found. 
 *  Stores the result in the given string. 
 *
 * @param[in] fd The file descriptor to read from.
 * @param[in,out] word The string in which the word read will be stored. In case it
 *  is NULL, memory will be allocated internally.
 * 
 * @return IOK or IERROR
 */
int misc_read_file_word(int fd, char **word);

/** 
 * @fn int misc_read_bstring_until(byte_t *string, byte_t *delimiter, uint32_t d_len,
 *                                 byte_t **output, uint64_t *read, uint8_t *finish)
 * @brief Reads the given binary string until the given delimiter (with the 
 *  specified length) or EOS is found, and stores the result in the given output. 
 *  If *output is NULL, memory will be allocated internally; otherwise, it must be 
 *  long enough to store the result, or the result will be truncated.
 *
 * @param[in] string The binary string to parse.
 * @param[in] s_len The length of the binary string, in bytes.
 * @param[in] delimiter The delimiter. If NULL, the function parses until EOS.
 * @param[in] d_len The length, in bytes, of the delimiter.
 * @param[in,out] output The string to store the result.
 * @param[in,out] read The number of bytes read, excluding the delimiter 
 *  (if found).
 * @param[in,out] finish Will be 1 if the delimiter was found, or 0 if the parsing
 *  ended due to EOS.
 * 
 * @return IOK or IERROR
 */
int misc_read_bstring_until(byte_t *string, uint64_t s_len, byte_t *delimiter, uint32_t d_len, 
			    byte_t **output, uint64_t *read, uint8_t *finish);

/** 
 * @fn int misc_read_file_to_bytestring(char *filename, byte_t **bytestring,
 *                                      uint64_t *b_len)
 * @brief Reads the given file into the given bytestring.
 *
 * @param[in] filename The name of the file to read.
 * @param[in,out] bytestring The byte string in wich the contents of the file
 *  will be stored. If NULL, memory will be internally allocated; otherwise,
 *  it must be big enough in order to store the contents of the file.
 * @param[in,out] b_len Will be set to the number of bytes read.
 * 
 * @return IOK or IERROR
 */
int misc_read_file_to_bytestring(char *filename, byte_t **bytestring, 
				 uint64_t *b_len);

/** 
 * @fn int misc_read_fd_to_bytestring(FILE *fd, byte_t **bytestring, 
			       uint64_t *b_len)
 * Similar to misc_read_file_to_bytestring, but reads from the specified file
 * descriptor. The file descriptor is repositioned to its original offset after
 * reading it. Only what's after the current position (at the moment of calling
 * the function) is read.
 *
 * @param[in] fd The file descriptor.
 * @param[in,out] bytestring The byte string in wich the contents of the file
 *  will be stored. If NULL, memory will be internally allocated; otherwise,
 *  it must be big enough in order to store the contents of the file.
 * @param[in,out] b_len Will be set to the number of bytes read.
 * 
 * @return IOK or IERROR
 */
int misc_read_fd_to_bytestring(FILE *fd, byte_t **bytestring, 
			       uint64_t *b_len);

/** 
 * @fn int misc_read_file_to_string(char *filename, char **bytestring, 
 *                                  uint64_t *b_len);
 * Same as misc_read_file_to_bytestring, but for files containing printable
 * strings.
 *
 * @param filename 
 * @param bytestring 
 * @param b_len 
 * 
 * @return IOK or IERROR
 */
int misc_read_file_to_string(char *filename, char **bytestring, 
			     uint64_t *b_len);

/** 
 * @fn int misc_fprintf_bytestring(FILE *fd, byte_t *bytestring, uint64_t b_len)
 * @brief Prints to the given file descriptor the given bytestring, of b_len bytes.
 *
 * @param[in] fd The file descriptor.
 * @param[in] bytestring The bytestring to print.
 * @param[in] b_len The length, in bytes, of bytestring.
 * 
 * @return IOK or IERROR
 */
int misc_fprintf_bytestring(FILE *fd, byte_t *bytestring, uint64_t b_len);

/** 
 * @fn int misc_bytes_to_file(char *filename, byte_t *bytes, uint64_t b_len)
 * @brief Prints to the given file descriptor the given array of bytes, 
 *  of b_len bytes.
 *
 * @param[in] filename The file name.
 * @param[in] bytestring The bytestring to print.
 * @param[in] b_len The length, in bytes, of bytestring.
 * 
 * @return IOK or IERROR
 */
int misc_bytes_to_file(char *filename, byte_t *bytes, uint64_t b_len);

/** 
 * @fn char* misc_int2string(int d)
 * Converts an int into a string.
 *
 * @param[in] d The int to convert to string.
 * 
 * @return A pointer to the string or NULL if error.
 */
char* misc_int2string(int d);

/** 
 * @fn char* misc_uint322string(uint32_t d)
 * Converts an uint32_t into a string.
 *
 * @param[in] d The uint32_t to convert to string.
 * 
 * @return A pointer to the string or NULL if error.
 */
char* misc_uint322string(uint32_t d);

/** 
 * @fn char* misc_uint642string(uint64_t d)
 * Converts an uint64_t into a string.
 *
 * @param[in] d The uint64_t to convert to string.
 * 
 * @return A pointer to the string or NULL if error.
 */
char* misc_uint642string(uint64_t d);

/** 
 * @fn char* misc_double2string(double d, const char *format)
 * Converts a double (formatted as specified) into a string.
 *
 * @param[in] d The double to convert to string.
 * @param[in] format The format (e.g. "%.3f")
 * 
 * @return A pointer to the string or NULL if error.
 */
char* misc_double2string(double d, const char *format);

/**
 * @fn int misc_wait_random_or_enter(time_t max_sec, uint8_t print)
 * Makes the process sleep a random time between 0 and max_sec seconds (with
 * nanoseconds precission) or until enter is pressed.
 *
 * @param[in] max_sec The maximum number of seconds to wait.
 * @param[in] print Print a message in stdout informing of the sleep time.
 *
 * @return IOK or IERROR
 *
 * @note Actually, the interruption by pressing enter is not implemented.
 */
int misc_wait_random_or_enter(time_t max_sec, uint8_t print);

/** 
 * @fn int misc_get_hex_representation(char **hex, byte_t *bytes, unsigned long len)
 * Calculates the hexadecimal representation (as a string) of the given byte array.
 *
 * @param[in,out] hex A string with the hexadecimal representation of bytes or NULL 
 *  if error.
 * @param[in] bytes The bytes to convert.
 * @param[in] len The number of bytes in bytes.
 * 
 * @return IOK or IERROR
 */
int misc_get_hex_representation(char **hex, byte_t *bytes, unsigned long len);

/** 
 * @fn int misc_fprintf_tabulated(FILE *stream, uint8_t tabs, uint32_t linelen, char *string)
 * Prints the received string in lines of 80 chars prepending 'tabs' tabs before
 * each line.
 *
 * @param[in] stream Where to print.
 * @param[in] tabs The number of tabs to prepend at the beginning of each line.
 * @param[in] linelen The number of chars to print per line.
 * @param[in] string The string to print.
 * 
 * @return IOK or IERROR
 */
int misc_fprintf_tabulated(FILE *stream, uint8_t tabs, uint32_t linelen, char *string);

#endif /* _MISC_H */

/* misc.h ends here */
