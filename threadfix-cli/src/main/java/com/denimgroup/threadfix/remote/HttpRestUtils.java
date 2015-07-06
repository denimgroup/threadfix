////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.remote.response.ResponseParser;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.apache.commons.httpclient.methods.multipart.StringPart;
import org.apache.commons.httpclient.protocol.Protocol;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLHandshakeException;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class HttpRestUtils {

    public static final String API_KEY_SEGMENT = "?apiKey=";

    @Nonnull
    final PropertiesManager propertiesManager;

    private boolean unsafeFlag = false;

    public static final String JAVA_KEY_STORE_FILE = getKeyStoreFile();

    private static int count;

    private static final SanitizedLogger LOGGER = new SanitizedLogger(HttpRestUtils.class);

    public HttpRestUtils(@Nonnull PropertiesManager manager) {
        this.propertiesManager = manager;
        System.setProperty("javax.net.ssl.trustStore", JAVA_KEY_STORE_FILE);
    }

    @Nonnull
	public <T> RestResponse<T> httpPostFile(@Nonnull String path,
                                            @Nonnull File file,
                                            @Nonnull String[] paramNames,
                                            @Nonnull String[] paramVals,
                                            @Nonnull Class<T> targetClass) {

        if (isUnsafeFlag())
            Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

        String completeUrl = makePostUrl(path);

		PostMethod filePost = new PostMethod(completeUrl);

		filePost.setRequestHeader("Accept", "application/json");

        RestResponse<T> response = null;
        int status = -1;

		try {
            Part[] parts = new Part[paramNames.length + 2];
            parts[paramNames.length] = new FilePart("file", file);
            parts[paramNames.length + 1] = new StringPart("apiKey", propertiesManager.getKey());

            for (int i = 0; i < paramNames.length; i++) {
                parts[i] = new StringPart(paramNames[i], paramVals[i]);
            }

            filePost.setRequestEntity(new MultipartRequestEntity(parts,
                    filePost.getParams()));

            filePost.setContentChunked(true);
            HttpClient client = new HttpClient();
            status = client.executeMethod(filePost);

            if (status != 200) {
                LOGGER.warn("Request for '" + completeUrl + "' status was " + status + ", not 200 as expected.");
            }

            if (status == 302) {
                Header location = filePost.getResponseHeader("Location");
                printRedirectInformation(location);
            }

            response = ResponseParser.getRestResponse(filePost.getResponseBodyAsStream(), status, targetClass);

        } catch (SSLHandshakeException sslHandshakeException) {

            importCert(sslHandshakeException);

        } catch (IOException e1) {
            LOGGER.error("There was an error and the POST request was not finished.", e1);
            response = ResponseParser.getErrorResponse(
                    "There was an error and the POST request was not finished.",
                    status);
        }

        return response;
    }

    @Nonnull
    public <T> RestResponse<T> httpPost(@Nonnull String path,
                                        @Nonnull String[] paramNames,
                                        @Nonnull String[] paramVals,
                                        @Nonnull Class<T> targetClass) {

        if (isUnsafeFlag())
            Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

        String urlString = makePostUrl(path);

		PostMethod post = new PostMethod(urlString);

		post.setRequestHeader("Accept", "application/json");

        int responseCode = -1;
        RestResponse<T> response = null;

		try {
			for (int i = 0; i < paramNames.length; i++) {
				if (paramNames[i] != null && paramVals[i] != null) {
					post.addParameter(paramNames[i], paramVals[i]);
				}
			}

            addApiKey(post);

			HttpClient client = new HttpClient();
			responseCode = client.executeMethod(post);
			if (responseCode != 200) {
                LOGGER.warn("Request for '" + urlString + "' status was " + responseCode + ", not 200 as expected.");
			}

            if (responseCode == 302) {
                Header location = post.getResponseHeader("Location");
                printRedirectInformation(location);
            }

            response = ResponseParser.getRestResponse(post.getResponseBodyAsStream(), responseCode, targetClass);

		} catch (SSLHandshakeException sslHandshakeException) {

            importCert(sslHandshakeException);

        } catch (IOException e1) {
            LOGGER.error("Encountered IOException while trying to post to " + path, e1);
            response = ResponseParser.getErrorResponse(
                    "There was an error and the POST request was not finished.",
                    responseCode);
		}

        return response;
	}

    private void printRedirectInformation(Header location) {
        LOGGER.warn("Location header for 302 response was: " + location);

        if (location != null && location.getValue() != null) {
            String target = location.getValue();

            if (target.contains("login.jsp")) {
                // this might be a ThreadFix server
                target = target.substring(0, target.indexOf("login.jsp")) + "rest";

                LOGGER.info("Based on the Location header, the correct URL should be: " + target);
                LOGGER.info("Set it with -s url " + target);
            }
        }
    }

    @Nonnull
    public <T> RestResponse<T> httpGet(@Nonnull String path, @Nonnull Class<T> targetClass) {
        return httpGet(path, "", targetClass);
    }

    @Nonnull
	public <T> RestResponse<T> httpGet(@Nonnull String path, @Nonnull String params,
                                       @Nonnull Class<T> targetClass) {

        String urlString = makeGetUrl(path, params);

		LOGGER.debug("Requesting " + urlString);
        if (isUnsafeFlag())
            Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));
		GetMethod get = new GetMethod(urlString);

		get.setRequestHeader("Accept", "application/json");

		HttpClient client = new HttpClient();

        int status = -1;
        RestResponse<T> response = null;

		try {
			status = client.executeMethod(get);

			if (status != 200) {
                LOGGER.error("Status was not 200. It was " + status);
			}

            if (status == 302) {
                Header location = get.getResponseHeader("Location");
                printRedirectInformation(location);
            }

            response = ResponseParser.getRestResponse(get.getResponseBodyAsStream(), status, targetClass);

		} catch (SSLHandshakeException sslHandshakeException) {

            importCert(sslHandshakeException);

        } catch (IOException e) {
            LOGGER.error("Encountered IOException while trying to post to " + path, e);
            response = ResponseParser.getErrorResponse("There was an error and the GET request was not finished.", status);
		}

		return response;
	}

    @Nonnull
    private String makeGetUrl(@Nonnull String path, @Nonnull String params) {
        String baseUrl = propertiesManager.getUrl();
        String apiKey  = propertiesManager.getKey();

        LOGGER.debug("Building GET url with path " + path + " and base url " + baseUrl);

        if (baseUrl.endsWith("/rest") && path.charAt(0) != '/') {
            baseUrl = baseUrl + "/";
        }

        String finishedUrl = baseUrl + path + API_KEY_SEGMENT + apiKey + "&" + params;

        LOGGER.debug("Returning " + finishedUrl);

        return finishedUrl;
    }

    @Nonnull
    private String makePostUrl(@Nonnull String path) {
        String baseUrl = propertiesManager.getUrl();

        LOGGER.debug("Building POST url with path " + path + " and base url " + baseUrl);

        if (baseUrl.endsWith("/rest") && path.charAt(0) != '/') {
            baseUrl = baseUrl + "/";
        }

        LOGGER.debug("Returning " + baseUrl + path);

        return baseUrl + path;
    }

    private void addApiKey(PostMethod post) {
        if (propertiesManager.getKey() == null) {
            throw new IllegalStateException("Please set your key before using this tool. Use the -s key <key> option.");
        } else {
            post.addParameter("apiKey", propertiesManager.getKey());
        }
    }

    public boolean isUnsafeFlag() {
        return unsafeFlag;
    }

    public void setUnsafeFlag(boolean unsafeFlag) {
        this.unsafeFlag = unsafeFlag;
    }

    private URI getURI() throws URISyntaxException {
        String baseUrl = propertiesManager.getUrl();
        URI uri = new URI(baseUrl);
        return uri;
    }

    private void importCert(SSLHandshakeException sslHandshakeException){
        if (count < 2) {
            LOGGER.warn("Unsigned certificate found. Trying to import it to Java KeyStore.");
            try {
                URI uri = getURI();
                String domain = uri.getHost();
                domain = domain.startsWith("www.") ? domain.substring(4) : domain;
                if (InstallCert.install(domain, uri.getPort())) {
                    count++;
                    LOGGER.info("Successfully imported certificate. Please run your command again.");
                }
            } catch (Exception e) {
                LOGGER.error("Error when tried to import certificate. ", e);
            }
        } else {
            LOGGER.error("Unsigned certificate found. We tried to import it but was not successful." +
                    "We recommend you import server certificate to the Java cacerts keystore, or add option -Dunsafe-ssl from command line to accept all unsigned certificates. " +
                    "Check out https://github.com/denimgroup/threadfix/wiki/Importing-Self-Signed-Certificates on how to import Self Signed Certificates.", sslHandshakeException);
        }
    }

    private static String getKeyStoreFile() {
        char SEP = File.separatorChar;
        File dir = new File(System.getProperty("java.home") + SEP
                + "lib" + SEP + "security");
        File file = new File(dir, "jssecacerts");
        if (file.isFile() == false) {
            file = new File(dir, "cacerts");
        }
        return file.getAbsolutePath();
    }
}