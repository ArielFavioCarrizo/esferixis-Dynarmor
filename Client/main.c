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
 * Módulo base - Cliente de Dynarmor
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

#include <errno.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "misc.h"
#include "cryptoparams.h"

unsigned char MAGICPROTOCOLHEADER[] = { 0xAF, 0xEA, 0x39, 0xE0, 0x67, 0x10, 0x20, 0xC9, 0x2F, 0xEB };
int32_t client_protocolversion = 0;

const unsigned short DEFAULTPORT=2250;

const char md_name[] = "sha512";
EVP_MD_CTX *mdctx;
const EVP_MD *md;

int socket_d;

bool initial_setup();
char * rsa_pubkey_load();

int reterror;

typedef struct {
	char aes_key[AES_KEY_BSIZE/8];
	char aes_iv[AES_IV_BSIZE/8];
} SESSION_KEY_DATA;

bool initial_setup() {
	/**
	 * Recibir cadena mágica del servidor, si no es igual o da error, significa que el protocolo es incorrecto
	 * o que hay un problema con la conexión
	 */
	char server_magicheader[sizeof(MAGICPROTOCOLHEADER)];
	if ( !secureread(socket_d, server_magicheader, sizeof(MAGICPROTOCOLHEADER)) || ( memcmp(server_magicheader, MAGICPROTOCOLHEADER, sizeof(MAGICPROTOCOLHEADER)) != 0 ) ) {
		fprintf(stderr, "Connection error or invalid protocol\n");
		reterror = 5;
	}
	else {
		int32_t server_protocolversion;
			
		// Enviar entero descriptor de versión de protocolo
		if ( !secure_int32_write(socket_d, client_protocolversion) ) {
			fprintf(stderr, "Connection error\n");
			reterror = 6;
		}
		else {
			char returnValue;
			// Recibir código de retorno
			if ( !secureread(socket_d, &returnValue, sizeof(char)) ) {
				fprintf(stderr, "Connection error\n");
				reterror = 6;
			}
			else {
				if ( returnValue != 0 ) {
					fprintf(stderr, "Invalid protocol version, outdated client\n");
					reterror = 11;
				}
			}
		}
	}

	return ( reterror == 0 );
}

char * rsa_pubkey_load() {
	char *pem_pubkey = NULL;

	buffer pubkey; // Clave pública
	pubkey.data = NULL;

	// Recibir clave pública
	if ( secure_int32_read(socket_d, &pubkey.size) ) {
		if ( (pubkey.size >= 1) && ( pubkey.size <= 1024 * 10 ) ) {
			pubkey.data = malloc(pubkey.size);
			if ( !secureread(socket_d, pubkey.data, pubkey.size) ) {
				fprintf(stderr, "Connection error\n");
				reterror = 6;
			}
		}
		else {
			fprintf(stderr, "Invalid public key size\n");
			reterror = 7;
		}
	}
	else {
		fprintf(stderr, "Connection error\n");
		reterror = 6;
	}

	if ( reterror == 0 ) {
		{
			char *base64_pubkey = encodedtobase64(pubkey.data, pubkey.size);
			char answer;

			printf("Public key from server:\n%s\nAccept? (S/n)\n", base64_pubkey);
			scanf(" %c", &answer);

			if ( answer != 'S' ) {
				fprintf(stderr, "Rejected key\n");
				reterror = 8;
			}
			else {
				pem_pubkey = base64topem(base64_pubkey, "-----BEGIN PUBLIC KEY-----\n", "\n-----END PUBLIC KEY-----\n");
			}
		}
	}

	if ( pubkey.data != NULL )
		free(pubkey.data);

	return pem_pubkey;
}

SESSION_KEY_DATA * session_key_setup(char *pem_pubkey) {
	// Si fue aceptada, generar una clave simétrica y su vector de inicialización, con su hash, todas cifradas, con la clave pública

	// Generar clave privada y su vector de inicialización
	struct {
		SESSION_KEY_DATA data;
		char md_value[EVP_MAX_MD_SIZE];
	} setup_message;

	if ( RAND_bytes( (unsigned char *) &setup_message.data, sizeof(SESSION_KEY_DATA) ) ) {
		// Calcular SHA512 de la clave privada y su vector de inicialización
		{
			int md_len;
			EVP_DigestInit_ex(mdctx, md, NULL);
			EVP_DigestUpdate(mdctx, (char *) &setup_message.data, sizeof(SESSION_KEY_DATA) );
			EVP_DigestFinal_ex(mdctx, setup_message.md_value, &md_len);
		}

		// Cifrar mensaje y enviarlo
		{
			// Crear "wrapper" para la clave pública
			BIO *bufio = bufio = BIO_new_mem_buf( (void *) pem_pubkey, -1 );
			RSA *rsa = RSA_new();
		
			if ( PEM_read_bio_RSA_PUBKEY( bufio, &rsa, 0, NULL ) ) {
				char *encrypted_msg = malloc( RSA_size( rsa ) );

				int encrypted_len;
		
				if ( ( encrypted_len = RSA_public_encrypt( sizeof(setup_message), (unsigned char *) &setup_message, (unsigned char *) encrypted_msg, rsa, RSA_PKCS1_PADDING) ) == -1 ) {
					char err[150];
					ERR_error_string_n(ERR_get_error(), err, sizeof(err));
					fprintf(stderr, "RSA encryption error\n");
					reterror = 11;
				}

				// Enviar longitud del mensaje cifrado y el mensaje respectivamente
				secure_int32_write(socket_d, encrypted_len);
				securewrite(socket_d, encrypted_msg, encrypted_len);

				RSA_free(rsa);
			}
			else {
				fprintf(stderr, "RSA pubkey read error\n");
				reterror = 10;
			}

			BIO_free(bufio);
		}
	}
	else {
		fprintf(stderr, "Cannot generate session key data");
		reterror = 12;
	}

	if ( reterror == 0 ) {
		SESSION_KEY_DATA *returnBuffer = malloc(sizeof(SESSION_KEY_DATA));
		memcpy( (void *) returnBuffer, (void *) &setup_message.data, sizeof(SESSION_KEY_DATA));

		return returnBuffer;
	}
	else {
		return NULL;
	}
}

int main(int argc, char *argv[]) {
	char *hostname;
	unsigned short portnumber;
	int reterror=0;

	struct sockaddr_in address;

	struct hostent *host;

	reterror = 0;

	{
		bool help = false;
		bool error = false;
		if ( argc > 2 ) {
			int i=0;
			for ( i=1 ; (i<argc) && (argv[i][0] == '-') ; i++) {
				char *eachArg = argv[i];
				if ( ( strcmp(eachArg, "-h") == 0 ) || ( strcmp(eachArg, "--help") == 0 ) ) {
					help = true;
					break;
				}
				else {
					fprintf(stderr, "Unrecognized option: '%s'\n", eachArg);
					error = true;
				}
			}

			if ( i != 1 ) {
				argv[i-1] = argv[0];
				argv = &argv[i-1];

				argc -= (i-1);
			}
		}

		if ( argc != 2 ) {
			fprintf(stderr, "Invalid parameters\n");
		}

		if ( error || help ) {
			printf("Usage: %s [options] <hostname>:[port number]\n\nOptions\n  -h, --help\n  -p, --profile <path>	Start with profile at <path>\n", argv[0]);
			return ( help ? 0 : 1);
		}
	}

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	mdctx = EVP_MD_CTX_create();
	
	if ( ( md = EVP_get_digestbyname(md_name) ) == NULL ) {
		fprintf(stderr, "Unexpected message digest error\n");
		reterror = 10;
	}
	
	// Obtener nombre de host y puerto
	hostname = argv[1];
	{
		char *eachCharacter = hostname;
		while ( (*eachCharacter != ':') && (*eachCharacter != 0) ) {
			eachCharacter++;
		}
		
		if ( *eachCharacter == ':' ) {
			*(eachCharacter++) = 0;
			char *portnumber_str = eachCharacter;
			sscanf(portnumber_str, "%hu", &portnumber);
		}
		else {
			portnumber = DEFAULTPORT;
		}
	}
	
	if ( ( host = gethostbyname(hostname) ) == NULL ) {
		fprintf(stderr, "Cannot get host\n");
		reterror = 2;
	}
	
	if ( ( socket_d = socket(AF_INET, SOCK_STREAM, 0) ) == -1 ) {
		fprintf(stderr, "Cannot open an socket\n");
		reterror = 3;
	}

	if ( reterror == 0 ) {

		address.sin_family = AF_INET;
		address.sin_addr.s_addr = ( ( struct in_addr* ) (host->h_addr))->s_addr;
		address.sin_port = htons(portnumber);
	
		if ( connect(socket_d, (struct sockaddr *) &address, sizeof(address)) == -1 ) {
			fprintf(stderr, "Cannot connect\n");
			reterror = 4;
		}

		if ( reterror == 0 ) {
			if ( initial_setup() ) {
				char *pem_pubkey = rsa_pubkey_load();

				if ( reterror == 0 ) {
					SESSION_KEY_DATA *session_key_data = session_key_setup(pem_pubkey);

					/**
					 * Recepción de código de máquina
					 */
				}

				free(pem_pubkey);
			}
		}
	}
	close(socket_d);
	
	EVP_MD_CTX_destroy(mdctx);
	EVP_cleanup();
	return reterror;
}
