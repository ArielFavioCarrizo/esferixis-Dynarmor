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
 * Cabecera de la capa de HMAC - Cliente de Dynarmor
 */

#ifndef _HMAC
#define _HMAC

#include <openssl/buffer.h>
#include <openssl/evp.h>
#include "misc.h"

typedef struct hmac_layer_buffer hmac_layer_buffer;

void hmac_layer_init(EVP_MD_CTX *mdctx_parameter, const EVP_MD *md_parameter);
char *hmac_layer_getkey(size_t *size);
hmac_layer_buffer * hmac_layer_createbuffer();
char * hmac_layer_buffer_allocmessage(hmac_layer_buffer *buffer, size_t size);
char * hmac_layer_buffer_encode(hmac_layer_buffer *buffer, size_t *encode_size);
char * hmac_layer_buffer_decode(hmac_layer_buffer *buffer, size_t *messageSize);
void hmac_layer_buffer_destroy(hmac_layer_buffer *buffer);
void hmac_layer_destroy();

#endif
