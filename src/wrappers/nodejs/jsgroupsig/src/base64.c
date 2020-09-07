/** 
 * The following is based on Jouni Malinen's code for base64 encoding, 
 * Original copyright license is copied verbatim.
 **/

/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <stdlib.h>
#include <string.h>

#include "base64.h"

static const unsigned char base64_table[65] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded. Must be a 0-ended string.
 * @len: Length of the data to be encoded
 * @nl: If 0, no '\n' chars will be added each 72 chars nor at the end.
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
char * base64_encode(const unsigned char *src, uint64_t len, uint8_t nl) {

  char *out, *pos;
  const unsigned char *end, *in;
  uint64_t olen, line_len;

  if (!src || !len) {
    return NULL;
  }

  olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
  if(nl) olen += olen / 72; /* line feeds */
  olen++; /* nul termination */
  if (olen < len)
    return NULL; /* integer overflow */
  out = malloc(olen*2);
  if (out == NULL)
    return NULL;

  end = src + len;
  in = src;
  pos = out;
  line_len = 0;
  while (end - in >= 3) {
    *pos++ = base64_table[in[0] >> 2];
    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = base64_table[in[2] & 0x3f];
    in += 3;
    line_len += 4;
    if (line_len >= 72 && nl) {
      *pos++ = '\n';
      line_len = 0;
    }
  }

  if (end - in) {
    *pos++ = base64_table[in[0] >> 2];
    if (end - in == 1) {
      *pos++ = base64_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
    } else {
      *pos++ = base64_table[((in[0] & 0x03) << 4) |
			    (in[1] >> 4)];
      *pos++ = base64_table[(in[1] & 0x0f) << 2];
    }
    *pos++ = '=';
    line_len += 4;
  }

  if (line_len && nl)
    *pos++ = '\n';

  *pos = '\0';
  return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded. Must be 0-terminated.
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char* base64_decode(const char *src, uint64_t *out_len) {
  
  unsigned char dtable[256], *out, *pos, block[4], tmp;
  uint64_t i, count, olen, pad, len;

  if(!src || !out_len) {
    return NULL;
  }

  len = strlen(src);
  pad = 0;
  
  memset(dtable, 0x80, 256);
  for (i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[base64_table[i]] = (unsigned char) i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++) {
    if (dtable[(uint8_t) src[i]] != 0x80)
      count++;
  }

  if (count == 0 || count % 4)
    return NULL;

  olen = count / 4 * 3;
  pos = out = malloc(olen*2);
  if (out == NULL)
    return NULL;

  count = 0;
  for (i = 0; i < len; i++) {
    tmp = dtable[(uint8_t) src[i]];
    if (tmp == 0x80)
      continue;

    if (src[i] == '=')
      pad++;
    block[count] = tmp;
    count++;
    if (count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad) {
	if (pad == 1)
	  pos--;
	else if (pad == 2)
	  pos -= 2;
	else {
	  /* Invalid padding */
	  free(out);
	  return NULL;
	}
	break;
      }
    }
  }

  *out_len = pos - out;
  return out;
}
