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
 * Módulo de misceláneas - Cliente de Dynarmor
 */

#include "misc.h"

bool secureread(int descriptor, char *data, int32_t size) {
	int32_t read_n = 0;
	int32_t aux = 0;
	
	errno = 0;
	
	while ( read_n < size ) {
		aux = read( descriptor, data + read_n, size - read_n);
		
		if ( aux > 0 ) {
			read_n += aux;
		}
		else if ( aux < 0 ) {
			fprintf(stderr, "Unexpected read error: %s\n", strerror(errno) );
			return false;
		} else if ( ( aux == 0 ) && ( read_n != size ) ) {
			fprintf(stderr, "Unexpected closed connection\n");
			return false;
		}
	}
	return true;
}

bool securewrite(int descriptor, char *data, int32_t size) {
	int32_t written = 0;
	int32_t aux = 0;
	
	while ( written < size ) {
		aux = write( descriptor, data + written, size - written);
		
		if ( aux > 0 ) {
			written += aux;
		}
		else if ( ( aux < 0 ) || ( written != size) ) {
			fprintf(stderr, "Unexpected write error\n");
			return false;
		}
	}
	return true;
}

bool secure_int32_read(int descriptor, int32_t *data) {
	if ( secureread(descriptor, (char *) data, sizeof(int32_t)) ) {
		*data = ntohl(*data);
		return true;
	}
	else {
		return false;
	}
}

bool secure_int32_write(int descriptor, int32_t data) {
	data = htonl(data);
	if ( securewrite(descriptor, (char *) &data, sizeof(int32_t)) ) {
		return true;
	}
	else {
		return false;
	}
}

bool send_data(int descriptor, char *data, uint32_t size, char *msg_err) {
	int returnvalue;
	bool invaliddata;

	if ( secure_int32_write(descriptor, size) ) {
		// Si se recibió 0 significa que fue aceptada, caso contrario fue rechazada
		if ( secureread(descriptor, (char *) &returnvalue, sizeof(char)) ) {

			if ( returnvalue == 0 ) {
				// Proceder a enviar datos (La clave en sí)
				if ( securewrite(descriptor, data, size) ) {
					// Si se recibió 0 significa que fue aceptada, caso contrario rechazada
					if ( secureread(descriptor, (char *) &returnvalue, sizeof(char)) ) {
						invaliddata = ( returnvalue != 0 );
					}
				}
			}
			else {
				invaliddata = true;
			}
		}

		if ( invaliddata ) {
			fprintf(stderr, "%s", msg_err);
		}
	}

	return ( returnvalue == 0 ) && ( !invaliddata);
}

char * encodedtobase64(const char *input, int32_t length) {
	BIO *bmem, *b64;
	BUF_MEM *bptr;
	
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = (char *) malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);

	return buff;
}

char * base64topem(char *input, char *pem_header, char *pem_foot) {
	size_t output_len = strlen(pem_header) + strlen(input) + strlen(pem_foot);
	
	char *output = malloc(output_len+1);
	snprintf(output, output_len+1, "%s%s%s", pem_header, input, pem_foot);

	return output;
}
