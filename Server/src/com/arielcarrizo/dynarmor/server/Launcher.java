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
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.logging.Logger;

import com.arielcarrizo.dynarmor.server.Configuration.LoadException;
import com.arielcarrizo.dynarmor.server.Configuration.ParseError;

public final class Launcher {
	private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	
	private Launcher() {};
	
	public static void main(String[] args) {
		if ( args != null ) {
			File serverConfigFile = null;
			
			Iterator<String> argsIterator = Arrays.asList(args).iterator();
			
			while ( argsIterator.hasNext() ) {
				String eachArg = argsIterator.next();
				switch ( eachArg ) {
				case "--help":
				case "-h":
					System.out.println(
							"Usage: dynarmorServer [options]\n\n" +
							"Options:\n" +
							"-f config		specifies the server config file (Required)"
					);
					break;
				case "-f":
					if ( argsIterator.hasNext() ) {
						serverConfigFile = new File(argsIterator.next());
						if ( !( serverConfigFile.exists() && serverConfigFile.isFile() ) ) {
							System.err.println("Invalid server config file");
							System.exit(2);
						}
					}
				}
			}
			
			if ( serverConfigFile != null ) {
				try {
					Configuration.load(serverConfigFile);
				} catch (LoadException e) {
					System.err.println("Error at loading server config file: '" + e.getCause() + "'");
					System.exit(3);
				} catch (ParseError e) {
					System.err.println("Server config file parse error: \"" + e.getMessage() + "\"");
					System.exit(4);
				}
			}
			else {
				System.err.println("Missing server config file");
				System.exit(1);
			}
		}
		
		LOGGER.info("Starting dynarmor server");
		
		try {
			ServerSocket serverSocket = new ServerSocket(Configuration.instance().getListenPort(), 10, Configuration.instance().getListenAddress() );
			(new Thread( new MultiThreadedServer(serverSocket) ) ).start();
		}
		catch ( IOException e ) {
			LOGGER.severe("Cannot create server socket: '" + e + "'");
		}
	}
}