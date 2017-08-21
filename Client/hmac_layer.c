/**
 * Copyright (c) 2017 Ariel Favio Carrizo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of 'esferixis' nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Capa de HMAC - Cliente de Dynarmor
 */

#include "hmac_layer.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/err.h>

struct hmac_layer_buffer {
	size_t messageSize;
	char *buffer;
};

EVP_MD_CTX *mdctx;
const EVP_MD *md;

unsigned char *hmac_key;
unsigned char *i_key_pad;
unsigned char *o_key_pad;

size_t md_block_size;

char * hmac_layer_buffer_calc(hmac_layer_buffer *buffer, char *output);

void hmac_layer_init(EVP_MD_CTX *mdctx_parameter, const EVP_MD *md_parameter) {
	mdctx = mdctx_parameter;
	md = md_parameter;
	md_block_size = EVP_MD_block_size(md);
	hmac_key = malloc(md_block_size*3);
	RAND_bytes( (unsigned char *) hmac_key, md_block_size);
	i_key_pad = &hmac_key[md_block_size*2];
	o_key_pad = &hmac_key[md_block_size*3];

	int32_t i;
	for ( i = 0 ; i<md_block_size; i++ ) {
		i_key_pad[i] = 0x36 ^ hmac_key[i];
		o_key_pad[i] = 0x5c ^ hmac_key[i];
	}
	free(hmac_key);
}

char *hmac_layer_getkey(size_t *size) {
	*size = md_block_size;
	return (char *) hmac_key;
}

hmac_layer_buffer * hmac_layer_createbuffer() {
	hmac_layer_buffer *buffer = malloc(sizeof(hmac_layer_buffer));
	buffer->messageSize = 0;
	buffer->buffer = NULL;
}

char * hmac_layer_buffer_allocmessage(hmac_layer_buffer *buffer, size_t size) {
	buffer->messageSize = size;
	if ( buffer->buffer != NULL ) {
		free(buffer->buffer);
	}

	buffer->buffer = malloc(size + md_block_size*3);
}

char * hmac_layer_buffer_calc(hmac_layer_buffer *buffer, char *output) {
	int md_length;
	
	// hash(i_key_pad || message)
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, i_key_pad, md_block_size);
	EVP_DigestUpdate(mdctx, buffer->buffer, buffer->messageSize);

	char *tmp_md = (char *) &buffer->buffer[buffer->messageSize + md_block_size];
	EVP_DigestFinal_ex(mdctx, tmp_md, &md_length);
	
	// hash(o_key_pad || hash(i_key_pad || message))
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, o_key_pad, md_block_size);
	EVP_DigestUpdate(mdctx, tmp_md, md_block_size);
	EVP_DigestFinal_ex(mdctx, output, &md_length);
}

char * hmac_layer_buffer_encode(hmac_layer_buffer *buffer, size_t *encode_size) {
	hmac_layer_buffer_calc(buffer, (char *) &buffer->buffer[buffer->messageSize]);
	*encode_size = buffer->messageSize + md_block_size;
	return buffer->buffer;
}

char * hmac_layer_buffer_decode(hmac_layer_buffer *buffer, size_t *messageSize) {
	char *buffer_hmac = &buffer->buffer[buffer->messageSize];
	char *calculated_hmac = (char *) &buffer->buffer[buffer->messageSize+md_block_size*2];
	hmac_layer_buffer_calc(buffer, calculated_hmac);

	if ( memcmp(buffer_hmac, calculated_hmac, md_block_size) == 0 ) {
		return buffer->buffer;
	}
	else {
		return NULL;
	}
}

void hmac_layer_buffer_destroy(hmac_layer_buffer *buffer) {
	if ( buffer->buffer != NULL )
		free(buffer->buffer);
}

void hmac_layer_destroy() {
	free(hmac_key);
}
