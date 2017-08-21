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

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Configuración del servidor
 * @author ariel
 *
 */
public class Configuration {
	public static class ParseError extends Exception {
		/**
		 * 
		 */
		private static final long serialVersionUID = -7079701915307872091L;
		private final Integer lineNumber;
		
		public ParseError(int lineNumber, String message) {
			super("'" + message + "', at " + lineNumber);
			this.lineNumber = lineNumber;
		}
		
		public ParseError(String message) {
			super(message);
			this.lineNumber = null;
		}
		
		/**
		 * @post Devuelve el número de línea
		 */
		public int getLineNumber() {
			return this.lineNumber;
		}
	}
	
	public static class LoadException extends Exception {
		/**
		 * 
		 */
		private static final long serialVersionUID = 8973584419989376552L;

		public LoadException(Exception e) {
			super(e);
		}
	}
	
	private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	
	private static Configuration instance = null;
	
	private File serverConfigFile;
	
	private InetAddress listenAddress;
	private int listenPort;
	
	private KeyPair keyPair;
	
	/**
	 * @pre La configuración no puede volverse a crear y el archivo
	 * 		tiene que ser legible
	 * @post Crea la configuración, con el archivo de configuración especificado
	 */
	public static void load(File serverConfigFile) throws LoadException, ParseError {
		if ( instance == null ) {
			instance = new Configuration(serverConfigFile);
		}
		else {
			throw new IllegalStateException("Attemped to reload configuration");
		}
	}
	
	/**
	 * @pre La configuración tiene que haber sido cargada anteriormente
	 * @post Recarga la configuración
	 * @param serverConfigFile
	 * @throws IOException
	 * @throws ParseError
	 */
	public static void reload() throws LoadException, ParseError {
		Configuration oldConfiguration = instance();
		instance = new Configuration(oldConfiguration.serverConfigFile);
	}
	
	private static byte[] readFile(File fileName) throws IOException {
		DataInputStream dataInputStream = new DataInputStream(new FileInputStream(fileName));
		byte[] binaryData = new byte[(int) fileName.length()];
		
		try {
			dataInputStream.readFully(binaryData);
		} finally {
			dataInputStream.close();
		}
		
		return binaryData;
	}
	
	private Configuration(File serverConfigFile) throws LoadException, ParseError {
		final KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		
		BufferedReader bufferedReader;
		try {
			bufferedReader = new BufferedReader(new FileReader(serverConfigFile));
		} catch (FileNotFoundException e) {
			throw new LoadException(e);
		}
		
		try {
			int lineNumber = 1;
			
			try {
				this.listenAddress = InetAddress.getLocalHost();
			} catch (UnknownHostException e) {
				throw new RuntimeException(e);
			}
			this.listenPort = 2250;
			
			String line;
			
			while ( ( line = bufferedReader.readLine() ) != null ) {
				line = line.trim();
				
				// Si no es una línea vacía ni un comentario
				if ( (!line.isEmpty()) && (line.charAt(0) != '#') ) {
					List<String> parameters = new ArrayList<String>();
					for ( String eachParameter : line.split(" ") ) {
						eachParameter = eachParameter.trim();
							
						if ( eachParameter != "" ) {
							parameters.add(eachParameter);
						}
					}
					
					switch ( parameters.get(0) ) {
					case "ListenAddress":
						if ( parameters.size() == 2 ) {
							try {
								this.listenAddress = InetAddress.getByName(parameters.get(1));
							}
							catch ( UnknownHostException e ) {
								throw new ParseError(lineNumber, "Invalid listen address");
							}
						}
						else {
							throw new ParseError(lineNumber, "Expected one parameter");
						}
						break;
					case "Port":
						if ( parameters.size() == 2 ) {
							try {
								this.listenPort = Integer.parseInt(parameters.get(1));
							} catch ( NumberFormatException e ) {
								throw new ParseError(lineNumber, "Invalid port number");
							}
						}
						else {
							throw new ParseError(lineNumber, "Expected one parameter");
						}
						break;
					case "LogFile":
						if ( parameters.size() == 2 ) {
							final String fileName = parameters.get(1);
							File logFile = new File(fileName);
							if ( !logFile.exists() || !logFile.canWrite() ) {
								throw new ParseError(lineNumber, "Log file doesn't exists or cannot written");
							}
							
							// Suprimir la salida de consola
							Handler[] handlers = LOGGER.getHandlers();
							if ( handlers[0] instanceof ConsoleHandler ) {
								LOGGER.removeHandler(handlers[0]);
							}
							
							// Agregar la salida por archivo de logs
							Handler asciiFileHandler = new FileHandler(fileName);
							{
								SimpleFormatter asciiFileFormatter = new SimpleFormatter();
								asciiFileHandler.setFormatter(asciiFileFormatter);
							}
							LOGGER.addHandler(asciiFileHandler);
						}
						else {
							throw new ParseError(lineNumber, "Expected one parameter");
						}
						break;
					case "PublicRSAKeyFile":
						if ( parameters.size() == 2 ) {
							EncodedKeySpec spec = new X509EncodedKeySpec( readFile( new File(parameters.get(1))) );
							try {
								publicKey = keyFactory.generatePublic(spec);
							} catch (InvalidKeySpecException e) {
								throw new LoadException(e);
							}
						}
						else {
							throw new ParseError(lineNumber, "Expected one parameter");
						}
						break;
					case "PrivateRSAKeyFile":
						if ( parameters.size() == 2 ) {
							EncodedKeySpec spec = new PKCS8EncodedKeySpec( readFile( new File(parameters.get(1))) );
							try {
								privateKey = keyFactory.generatePrivate(spec);
							} catch (InvalidKeySpecException e) {
								throw new LoadException(e);
							}
						}
						else {
							throw new ParseError(lineNumber, "Expected one parameter");
						}
						break;
					default:
						throw new ParseError(lineNumber, "Bad configuration option, '" + parameters.get(0) + "'");
					}
				}
				lineNumber++;
			}
			
			if ( publicKey == null ) {
				throw new ParseError("Missing public key");
			}
			
			if ( privateKey == null ) {
				throw new ParseError("Missing private key");
			}
			
			this.keyPair = new KeyPair(publicKey, privateKey);
		} catch (IOException e) {
			throw new LoadException(e);
		} finally {
			try {
				bufferedReader.close();
			} catch (IOException e) {
				throw new LoadException(e);
			}
		}
	}
	
	/**
	 * @pre La configuración tiene que haber sido cargada
	 * @post Devuelve la instancia
	 */
	public static Configuration instance() {
		if ( instance != null ) {
			return instance;
		}
		else {
			throw new IllegalStateException("Attemped to get configuration without loading it");
		}
	}
	
	/**
	 * @post Devuelve la dirección de escucha
	 */
	public InetAddress getListenAddress() {
		return this.listenAddress;
	}
	
	/**
	 * @post Devuelve el puerto de escucha
	 */
	public int getListenPort() {
		return this.listenPort;
	}
	
	/**
	 * @post Devuelve el par de claves
	 */
	public KeyPair getKeyPair() {
		return this.keyPair;
	}
}
