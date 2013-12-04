////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.plugins.intellij.rest;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;

public class AcceptAllTrustFactory implements ProtocolSocketFactory {

	private SSLContext sslContext = null;

	private SSLContext createAcceptAllSSLContext() {
		try {
			AcceptAllTrustManager acceptAllTrustManager = new AcceptAllTrustManager();
			SSLContext context = SSLContext.getInstance("TLS");
			context.init(null,
					new AcceptAllTrustManager[] { acceptAllTrustManager },
					null);
			return context;
		} catch (KeyManagementException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

    private SSLContext getSSLContext() {
        if(this.sslContext == null) {
            this.sslContext = createAcceptAllSSLContext();
        }

        return this.sslContext;
    }

    @Override
	public Socket createSocket(String host, int port, InetAddress clientHost, int clientPort) throws IOException {
        return getSSLContext().getSocketFactory().createSocket(host, port, clientHost, clientPort);
    }

    @Override
	public Socket createSocket(final String host, final int port, final InetAddress localAddress, final int localPort, final HttpConnectionParams params) throws IOException {
        if(params == null) {
            throw new IllegalArgumentException("Parameters may not be null");
        }

        int timeout = params.getConnectionTimeout();
        SocketFactory socketFactory = getSSLContext().getSocketFactory();

        if(timeout == 0) {
            return socketFactory.createSocket(host, port, localAddress, localPort);
        }

        else {
            Socket socket = socketFactory.createSocket();
            SocketAddress localAddr = new InetSocketAddress(localAddress, localPort);
            SocketAddress remoteAddr = new InetSocketAddress(host, port);
            socket.bind(localAddr);
            socket.connect(remoteAddr, timeout);
            return socket;
        }
    }

    @Override
	public Socket createSocket(String host, int port) throws IOException {
        return getSSLContext().getSocketFactory().createSocket(host, port);
    }
    
    private class AcceptAllTrustManager implements X509TrustManager {
        @Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
        @Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
        @Override
		public X509Certificate[] getAcceptedIssuers() { return null; }
    }
}