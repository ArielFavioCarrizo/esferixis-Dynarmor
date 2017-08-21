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

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;

public class MultiThreadedServer implements Runnable {
	final static byte[] MAGICPROTOCOLHEADER = { (byte) 0xAF, (byte) 0xEA, 0x39, (byte) 0xE0, 0x67, 0x10, 0x20, (byte) 0xC9, 0x2F, (byte) 0xEB };
	final static int PROTOCOLVERSION = 0;
	
	private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	
	private final ServerSocket serverSocket;
	
	protected Thread runningThread;
	protected boolean isStopped;
	
	/**
	 * @pre El socket no puede ser nulo
	 * @post Crea el servidor con el socket de servidor especificado
	 */
	public MultiThreadedServer(ServerSocket serverSocket) {
		if ( serverSocket != null ) {
			this.serverSocket = serverSocket;
			this.runningThread = null;
			this.isStopped = false;
		}
		else {
			throw new NullPointerException();
		}
	}

	@Override
	public void run() {
		synchronized(this) {
			this.runningThread = Thread.currentThread();
		}
		
		while ( !this.isStopped() ) {
			Socket clientSocket = null;
			
			try {
				clientSocket = this.serverSocket.accept();
			} catch ( IOException e ) {
				if ( !this.isStopped() ) {
					LOGGER.warning("Error accepting client connection: '" + e + "'");
				}
				else {
					return;
				}
			}
			
			new Thread( new WorkerRunnable(clientSocket) ).start();
		}
	}
	
	private synchronized boolean isStopped() {
		return this.isStopped;
	}
	
	public synchronized void stop() {
		this.isStopped = true;
		
		try {
			this.serverSocket.close();
		} catch ( IOException e ) {
			LOGGER.severe("Error closing server socket: '" + e + "'");
		}
	}
}
