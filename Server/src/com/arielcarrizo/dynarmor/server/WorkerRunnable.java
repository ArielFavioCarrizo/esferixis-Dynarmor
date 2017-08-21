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

package com.arielcarrizo.dynarmor.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class WorkerRunnable implements Runnable {
	private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	
	protected final Socket clientSocket;
	
	/**
	 * @post Crea el runnable trabajador con el socket de cliente especificado
	 */
	public WorkerRunnable(Socket clientSocket) {
		this.clientSocket = clientSocket;
	}
	
	private static void logClientConnectionException(IOException e) {
		LOGGER.warning("Client connection error: '" + e + "'");
	}
	
	@Override
	public void run() {
		// Esperar 30 segundos
		try {
			this.clientSocket.setSoTimeout(30*1000);
		} catch (SocketException e) {
			logClientConnectionException(e);
		}
		
		DataInputStream input = null;
		DataOutputStream output = null;
		try {
			input = new DataInputStream(this.clientSocket.getInputStream());
			output = new DataOutputStream(this.clientSocket.getOutputStream());
		} catch (IOException e) {
			logClientConnectionException(e);
		}
		
		try {
			if ( ( input != null ) && ( output != null ) ) {
				// Enviar cadena "mágica"
				output.write(MultiThreadedServer.MAGICPROTOCOLHEADER);
				
				// Recibir número de versión de protocolo del cliente, si
				// no es igual, rechazar
				if ( input.readInt() == MultiThreadedServer.PROTOCOLVERSION ) {
					output.writeByte(0); // Indicar que la versión fue aceptada
					
					KeyPair keyPair = Configuration.instance().getKeyPair();
					PublicKey publicKey = keyPair.getPublic();
					
					// Enviar clave pública
					{
						byte[] publicKeyData = publicKey.getEncoded();
						output.writeInt(publicKeyData.length);
						output.write(publicKeyData);
					}
					
					byte[] decryptedSessionKeyData = null;
					
					{
						/** 
						 * Recibir clave privada con los vectores de inicialización y el hash respectivo.
						 * Todo cifrado con la clave pública.
						 */
						byte[] encryptedSessionKeyData;
						{
							int encryptedMessageLength = input.readInt();
							if ( ( encryptedMessageLength >= 1 ) && ( encryptedMessageLength <= 1024 * 10 ) ) {
								encryptedSessionKeyData = new byte[encryptedMessageLength];
								input.readFully(encryptedSessionKeyData);
								
								final Cipher cipher;
								cipher = Cipher.getInstance(SessionEncryptionSettings.RSA_SETUP);
								cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
								
								try {
									decryptedSessionKeyData = cipher.doFinal(encryptedSessionKeyData);
								} catch (Exception e) {
									LOGGER.warning("Cannot decrypt session key data: '" + e + "'");
								}
							}
							else {
								LOGGER.warning("Invalid client encrypted session key data size");
							}
						}
					}
					
					if ( decryptedSessionKeyData != null ) {
						/**
						 * Extrae la clave y el IV, y verifica
						 * que no hayan sido modificados
						 */
						MessageDigest md = SessionEncryptionSettings.MESSAGE_DIGEST;
						
						int offset = 0;
						byte[] aesKey_iv = Arrays.copyOfRange(decryptedSessionKeyData, offset, offset += (SessionEncryptionSettings.AES_SESSION_KEY_BITS_SIZE + SessionEncryptionSettings.AES_SESSION_IV_BITS_SIZE) / 8);
						byte[] hash = Arrays.copyOfRange(decryptedSessionKeyData, offset, offset += md.getDigestLength());
						
						// Calcular hash y verificar que sea igual
						if ( Arrays.equals(hash, md.digest(aesKey_iv)) ) {
							
						}
						else {
							LOGGER.warning("Tampered encrypted session key");
						}
					}
				}
				else {
					output.writeByte(1); // Indicar que la versión fue rechazada
				}
				
			}
		} catch (IOException e) {
			logClientConnectionException(e);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			LOGGER.severe(e.toString());
		} finally {
			if ( output != null ) {
				try {
					output.close();
				} catch (IOException e) {
					logClientConnectionException(e);
				}
			}
			
			if ( input != null ) {
				try {
					input.close();
				} catch (IOException e) {
					logClientConnectionException(e);
				}
			}
			
			try {
				this.clientSocket.close();
			} catch (IOException e) {
				logClientConnectionException(e);
			}
		}
	}
	
	
}
