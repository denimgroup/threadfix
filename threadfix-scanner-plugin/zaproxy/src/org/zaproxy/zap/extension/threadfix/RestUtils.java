package org.zaproxy.zap.extension.threadfix;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
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

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.apache.commons.httpclient.methods.multipart.StringPart;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

/**
 * Created by mac on 9/23/13.
 */
public class RestUtils {

    private static Logger logger = Logger.getLogger(ReportGenerator.class);

    private RestUtils(){}

    public static int uploadScan(File file) {
        if (getKey() == null || getUrl() == null) {
            return -2;
        } else {
            return httpPostFile(getUrl() + "/applications/" + getApplicationId() + "/upload",
                file,
                new String[] { "apiKey"  },
                new String[] { getKey()  });
        }
    }

    private static String getKey() {
        String key = ThreadFixPropertiesManager.getKey();
        logger.info("getKey is returning " + key);
        return key;
    }

    private static String getUrl() {
        String url = ThreadFixPropertiesManager.getUrl();
        logger.info("getUrl is returning " + url);
        return url;
    }

    private static String getApplicationId() {
        return ThreadFixPropertiesManager.getAppId();
    }

    public static String getApplications() {
        String result = httpGet(getUrl() + "/code/applications/?apiKey=" + getKey());

        return result;
    }

    public static String getEndpoints() {
        String result = httpGet(getUrl() + "/code/applications/" + getApplicationId() + "/endpoints?apiKey=" + getKey());

        return result;
    }

    public static String httpGet(String urlStr) {

        System.out.println("Requesting " + urlStr);

        Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));
        GetMethod get = new GetMethod(urlStr);

        HttpClient client = new HttpClient();
        try {
            int status = client.executeMethod(get);
            if (status != 200) {
                System.err.println("Status was not 200.");
            }

            InputStream responseStream = get.getResponseBodyAsStream();

            if (responseStream != null) {
                return IOUtils.toString(responseStream);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "There was an error and the GET request was not finished.";
    }

    private static int httpPostFile(String request, File file, String[] paramNames,
                               String[] paramVals) {

        int status = -1;

        Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

        PostMethod filePost = new PostMethod(request);

        filePost.setRequestHeader("Accept", "application/json");

        logger.info("Entering try/catch block");

        try {
            Part[] parts = new Part[paramNames.length + 1];
            parts[paramNames.length] = new FilePart("file", file);

            for (int i = 0; i < paramNames.length; i++) {
                parts[i] = new StringPart(paramNames[i], paramVals[i]);
            }

            filePost.setRequestEntity(new MultipartRequestEntity(parts,
                    filePost.getParams()));

            filePost.setContentChunked(true);
            HttpClient client = new HttpClient();
            status = client.executeMethod(filePost);
            logger.info("Status was " + status);

            if (status != 200) {
                System.err.println("Status was not 200.");
            }

            try (InputStream responseStream = filePost.getResponseBodyAsStream()) {
                if (responseStream != null) {
                    logger.debug("Got response text.");
                }
            }

        } catch (IOException e) {
            logger.info(e.getMessage(), e);
        }

        return status;
    }

    /**
     * These two classes allow the self-signed SSL cert to work. We might be able to cut this down.
     * @author mcollins
     *
     */
    public static class AcceptAllTrustManager implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }

    public static class AcceptAllTrustFactory implements ProtocolSocketFactory {

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

        public Socket createSocket(String host, int port, InetAddress clientHost, int clientPort) throws IOException {
            return getSSLContext().getSocketFactory().createSocket(host, port, clientHost, clientPort);
        }

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

        public Socket createSocket(String host, int port) throws IOException {
            return getSSLContext().getSocketFactory().createSocket(host, port);
        }

        public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
            return getSSLContext().getSocketFactory().createSocket(socket, host, port, autoClose);
        }
    }

}
