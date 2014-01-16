package burp.extention;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class RestUtils {

    private RestUtils(){}

    public static int uploadScan(File file) {
        if (getKey() == null || getUrl() == null) {
            return -2;
        } else {
            return httpPostFile(getUrl() + "/applications/" + getApplicationId() + "/upload",
                file);
        }
    }

    private static String getKey() {
        String key = ThreadFixPropertiesManager.getKey();
        return key;
    }

    private static String getUrl() {
        String url = ThreadFixPropertiesManager.getUrl();
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
        StringBuffer response = new StringBuffer();
        try {
            URL url = new URL(urlStr);
            HttpURLConnection urlconn = (HttpURLConnection) url.openConnection();
            urlconn.setRequestMethod("GET");
            urlconn.setRequestProperty("Accept", "application/json");
            urlconn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");

            urlconn.getResponseCode();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(urlconn.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append("\n" + inputLine);
            }
            in.close();
            urlconn.disconnect();

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return "error";
        }
        return response.toString();
    }

    private static int httpPostFile(String request, File file) {

        int status = -1;
        String charset = "UTF-8";
        try {
            MultipartUtility multipart = new MultipartUtility(request, charset);
            multipart.addHeaderField("Accept", "application/json");
            multipart.addFormField("apiKey", getKey());
            multipart.addFilePart("file", file);
            status = multipart.finish();
        } catch (IOException ex) {
        }

        return status;
    }

    /**
     * These two classes allow the self-signed SSL cert to work. We might be able to cut this down.
     * @author mcollins
     *
     */
    public static class AcceptAllTrustManager implements X509TrustManager {
        @Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
        @Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
        @Override
		public X509Certificate[] getAcceptedIssuers() { return null; }
    }

//    public static class AcceptAllTrustFactory implements ProtocolSocketFactory {
//
//        private SSLContext sslContext = null;
//
//        private SSLContext createAcceptAllSSLContext() {
//            try {
//                AcceptAllTrustManager acceptAllTrustManager = new AcceptAllTrustManager();
//                SSLContext context = SSLContext.getInstance("TLS");
//                context.init(null,
//                        new AcceptAllTrustManager[] { acceptAllTrustManager },
//                        null);
//                return context;
//            } catch (KeyManagementException e) {
//                e.printStackTrace();
//            } catch (NoSuchAlgorithmException e) {
//                e.printStackTrace();
//            }
//            return null;
//        }
//
//        private SSLContext getSSLContext() {
//            if(this.sslContext == null) {
//                this.sslContext = createAcceptAllSSLContext();
//            }
//
//            return this.sslContext;
//        }
//
//        @Override
//		public Socket createSocket(String host, int port, InetAddress clientHost, int clientPort) throws IOException {
//            return getSSLContext().getSocketFactory().createSocket(host, port, clientHost, clientPort);
//        }
//
//        @Override
//		public Socket createSocket(final String host, final int port, final InetAddress localAddress, final int localPort, final HttpConnectionParams params) throws IOException {
//            if(params == null) {
//                throw new IllegalArgumentException("Parameters may not be null");
//            }
//
//            int timeout = params.getConnectionTimeout();
//            SocketFactory socketFactory = getSSLContext().getSocketFactory();
//
//            if(timeout == 0) {
//                return socketFactory.createSocket(host, port, localAddress, localPort);
//            }
//
//            else {
//                Socket socket = socketFactory.createSocket();
//                SocketAddress localAddr = new InetSocketAddress(localAddress, localPort);
//                SocketAddress remoteAddr = new InetSocketAddress(host, port);
//                socket.bind(localAddr);
//                socket.connect(remoteAddr, timeout);
//                return socket;
//            }
//        }
//
//        @Override
//		public Socket createSocket(String host, int port) throws IOException {
//            return getSSLContext().getSocketFactory().createSocket(host, port);
//        }
//
//        public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
//            return getSSLContext().getSocketFactory().createSocket(socket, host, port, autoClose);
//        }
//    }

}
