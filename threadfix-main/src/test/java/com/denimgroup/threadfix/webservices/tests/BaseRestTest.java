package com.denimgroup.threadfix.webservices.tests;

import java.io.File;
import java.io.FileNotFoundException;
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

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import com.denimgroup.threadfix.cli.ThreadFixRestClientImpl;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
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
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This class provides methods for posting GET and POST requests with optional files,
 * as well as a place to put methods and data that would be useful for all REST testing.
 * @author mcollins
 *
 */
public abstract class BaseRestTest {
	
	protected final Log log = LogFactory.getLog(this.getClass());
	
	public static final String GOOD_API_KEY       = "mhD3Ek0mK04ejfxA7DTccrNiABXo3PAAzxYQZ25Ac";
	public static final String BAD_API_KEY        = "U1otLaZxwQLbsHZ2ifYtbPwbD1H4kcNgedWVIWn0";
	public static final String RESTRICTED_API_KEY = "PsjLL0KUXG8J9hkC2kpvFAGllJFPaZRskomeZiB9wSc";
	public static final String BASE_URL           = "http://localhost:8080/threadfix/rest";
	public static final String RESTRICTED_URL_NOT_RETURNED = "The restricted URL error was not returned correctly.";
	public static final String RESTRICTED_URL_RETURNED     = "The restricted URL error was returned when it shouldn't have been.";

	public static ThreadFixRestClient getGoodClient() {
        ThreadFixRestClient goodClient = new ThreadFixRestClientImpl();
		goodClient.setMemoryKey(GOOD_API_KEY);
		goodClient.setMemoryUrl(BASE_URL);
		return goodClient;
	}
	
	public String httpPostFile(String request, String fileName, String[] paramNames,
			String[] paramVals) {
		File file = new File(fileName);
		return httpPostFile(request, file, paramNames,
				paramVals);
	}
	
	public String httpPostFile(String request, File file, String[] paramNames,
			String[] paramVals) {
		
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

		PostMethod filePost = new PostMethod(request);
		
		filePost.setRequestHeader("Accept", "application/json");
		
		String result = null;
		InputStream responseStream = null;
		
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
			int status = client.executeMethod(filePost);
			if (status != 200) {
				log.debug("Status was not 200.");
			}
			
			responseStream = filePost.getResponseBodyAsStream();
			
			if (responseStream != null) {
				result = IOUtils.toString(responseStream);
			}

		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (responseStream != null) {
				try {
					responseStream.close();
				} catch (IOException e) {
					log.warn("IOException encountered while attempting to close a stream.", e);
				}
			}
		}
		
		if (result == null) {
			return "There was an error and the POST request was not finished.";
		} else {
			return result;
		}
	}

	public String httpPost(String request, String[] paramNames,
			String[] paramVals) {
		
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));
	
		PostMethod post = new PostMethod(request);
		
		post.setRequestHeader("Accept", "application/json");
		
		try {
			for (int i = 0; i < paramNames.length; i++) {
				post.addParameter(paramNames[i], paramVals[i]);
			}
			
			HttpClient client = new HttpClient();
			int status = client.executeMethod(post);
			if (status != 200) {
				log.debug("Status was not 200.");
			}
			
			InputStream responseStream = post.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return IOUtils.toString(responseStream);
			}
	
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	
		return "There was an error and the POST request was not finished.";
	}

	public String httpGet(String urlStr) {
		
		log.debug("Requesting " + urlStr);
		
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));
		GetMethod get = new GetMethod(urlStr);
		
		get.setRequestHeader("Accept", "application/json");
		
		HttpClient client = new HttpClient();
		try {
			int status = client.executeMethod(get);
			if (status != 200) {
				log.debug("Status was not 200.");
			}
			
			InputStream responseStream = get.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return IOUtils.toString(responseStream);
			}
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return "There was an error and the GET request was not finished.";
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * @param responseContents
	 * @return
	 */
	protected JSONObject getJSONObject(String responseContents) {
		try {
			return new JSONObject(responseContents);
		} catch (JSONException e) {
			log.warn("JSON Parsing failed.");
			return null;
		}
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * @param object
	 * @return
	 */
	protected Integer getId(JSONObject object) {
		try {
			return object.getInt("id");
		} catch (JSONException e) {
			log.warn("Failed when trying to parse an ID out of the object.");
			return null;
		}
	}
	
	protected String getString(JSONObject object, String key) {
		try {
			return object.getString(key);
		} catch (JSONException e) {
			log.warn("Failed when trying to parse " + key + " out of a JSON object.");
			return null;
		}
	}
	
	protected JSONArray getJSONArray(String responseContents) {
		try {
			return new JSONArray(responseContents);
		} catch (JSONException e) {
			log.warn("JSON Parsing failed.");
			return null;
		}
	}

	/**
	 * This method is a wrapper for RandomStringUtils.random with a preset character set.
	 * @return random string
	 */
	protected String getRandomString(int length) {
		return RandomStringUtils.random(length,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	}
	
	/**
	 * These two classes allow the self-signed SSL cert to work. We might be able to cut this down.
	 * @author mcollins
	 *
	 */
	public class AcceptAllTrustManager implements X509TrustManager {
	    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
	    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
	    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
	}
	
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
