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
package com.denimgroup.threadfix.service.defects.utils;

import com.denimgroup.threadfix.exception.RestException;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.exception.RestUrlException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ProxyService;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLHandshakeException;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * This class holds code for more easily interacting with HTTP-authenticated REST services.
 * So far this is just JIRA but this code could be useful in other places too.
 *
 * WARNING this class throws subclasses of RestException, so our error handler will return REST responses
 * to the user if the exceptions are not caught.
 * 
 * TODO further genericize and move to threadfix common code
 * @author mcollins
 *
 */
public class RestUtilsImpl<T> extends SpringBeanAutowiringSupport implements RestUtils {

    @Autowired(required = false)
    private ProxyService proxyService;

	private RestUtilsImpl() {} // intentional, we shouldn't be instantiating this class.

    Class<T> classToProxy = null;

	private static final SanitizedLogger LOG = new SanitizedLogger(RestUtilsImpl.class);
    private String postErrorResponse;

    public static <T> RestUtilsImpl getInstance(Class<T> classToProxy) {
        RestUtilsImpl impl = new RestUtilsImpl();
        impl.classToProxy = classToProxy;
        return impl;
    }

    private int getStatusCode(HttpURLConnection httpConnection) {
        int statusCode = -1;
        if (httpConnection != null) {
            try {
                statusCode = httpConnection.getResponseCode();
            } catch (IOException e1) {
                LOG.error("Encountered IOException while requesting response code from httpconnection object. " +
                        "Re-throwing initial exception.");

            }
        }
        return statusCode;
    }

    @Nonnull
	private InputStream getUrl(String urlString, String username, String password) throws RestException {
		URL url;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			throw new RestUrlException(e, "Unable to make request due to malformed URL. Check the code.");
		}

		HttpURLConnection httpConnection = null;
		try {
            if (proxyService == null) {
			    httpConnection = (HttpURLConnection) url.openConnection();
            } else {
                httpConnection = proxyService.getConnectionWithProxyConfig(url, classToProxy);
            }

			setupAuthorization(httpConnection, username, password);

			httpConnection.addRequestProperty("Content-Type", "application/json");
			httpConnection.addRequestProperty("Accept", "application/json");

			InputStream stream = httpConnection.getInputStream();

            return stream;
		} catch (IOException e) {
            LOG.info("Encountered IOException, unable to continue");
		    throw new RestIOException(e, "Unable to communicate with the server.", getStatusCode(httpConnection));
		}
	}

	public String getUrlAsString(String urlString, String username, String password) throws RestException {

        LOG.debug("Requesting " + urlString);

		InputStream responseStream = getUrl(urlString,username,password);

		String test = null;
		try {
			test = IOUtils.toString(responseStream);
		} catch (IOException e) {
			throw new RestIOException(e, "Unable to get response from server." + e.toString());
		} finally {
			closeInputStream(responseStream);
		}

		return test;
	}

	public void closeInputStream(InputStream stream) {
		if (stream != null) {
			try {
				stream.close();
			} catch (IOException ex) {
				LOG.warn("Closing an input stream failed.", ex);
			}
		}
	}

    @Nonnull
    private InputStream postUrl(String urlString, String data, String username, String password, String contentType) {
		URL url;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			LOG.warn("URL used for POST was bad: '" + urlString + "'");
			throw new RestUrlException(e, "Received a malformed server URL.");
		}

		HttpURLConnection httpConnection = null;
		OutputStreamWriter outputWriter = null;
		try {
            if (proxyService == null) {
                httpConnection = (HttpURLConnection) url.openConnection();
            } else {
                httpConnection = proxyService.getConnectionWithProxyConfig(url, classToProxy);
            }

			setupAuthorization(httpConnection, username, password);

			httpConnection.addRequestProperty("Content-Type", contentType);
			httpConnection.addRequestProperty("Accept", contentType);

			httpConnection.setDoOutput(true);
			outputWriter = new OutputStreamWriter(httpConnection.getOutputStream());
		    outputWriter.write(data);
		    outputWriter.flush();

			InputStream is = httpConnection.getInputStream();

			return is;
		} catch (IOException e) {
			LOG.warn("IOException encountered trying to post to URL with message: " + e.getMessage());
			if(httpConnection == null) {
				LOG.warn("HTTP connection was null so we cannot do further debugging of why the HTTP request failed");
			} else {
				try {
					InputStream errorStream = httpConnection.getErrorStream();
					if(errorStream == null) {
						LOG.warn("Error stream from HTTP connection was null");
					} else {
						LOG.warn("Error stream from HTTP connection was not null. Attempting to get response text.");
                        setPostErrorResponse(IOUtils.toString(errorStream));
						LOG.warn("Error text in response was '" + getPostErrorResponse() + "'");
                        throw new RestIOException(e, getPostErrorResponse(),
                                "Unable to get response from server. Error text was: " +
                                getPostErrorResponse(), getStatusCode(httpConnection));
					}
				} catch (IOException e2) {
					LOG.warn("IOException encountered trying to read the reason for the previous IOException: "
                            + e2.getMessage(), e2);
                    throw new RestIOException(e2, "Unable to read response from server." + e2.getMessage(), getStatusCode(httpConnection));
				}
			}
            throw new RestIOException(e, "Unable to read response from server." + e.toString());
        } finally {
			if (outputWriter != null) {
				try {
					outputWriter.close();
				} catch (IOException e) {
					LOG.warn("Failed to close output stream in postUrl.", e);
				}
			}
		}
	}
	
	public String postUrlAsString(String urlString, String data, String username, String password, String contentType)
            throws RestException {
		InputStream responseStream = postUrl(urlString, data, username, password, contentType);
		
		String test = null;
		try {
            test = IOUtils.toString(responseStream);
		} catch (IOException e) {
			throw new RestIOException(e, "Unable to parse response from server.");
		} finally {
			closeInputStream(responseStream);
		}
		
		return test;
	}
	
	private void setupAuthorization(HttpURLConnection connection,
			String username, String password) {
		String login = username + ":" + password;

		String encodedLogin = DatatypeConverter.printBase64Binary(login.getBytes());
		connection.setRequestProperty("Authorization", "Basic " + encodedLogin);
	}

    public String getPostErrorResponse() {
        return postErrorResponse;
    }

    private void setPostErrorResponse(String postErrorResponse) {
        this.postErrorResponse = postErrorResponse;
    }

    /**
     *
     * @param urlString JIRA URL to connect to
     * @return true if we get an HTTP 401, false if we get another HTTP response code (such as 200:OK)
     * 		or if an exception occurs
     */
    public boolean requestHas401Error(String urlString) {
        LOG.info("Checking to see if we get an HTTP 401 error for the URL '" + urlString + "'");

        boolean retVal;

        HttpClient httpClient;
        try {
            if (proxyService == null) {
                httpClient = new HttpClient();
            } else {
                httpClient = proxyService.getClientWithProxyConfig(classToProxy);
            }

            GetMethod get = new GetMethod(urlString);

            int responseCode = httpClient.executeMethod(get);

            retVal = responseCode == HttpURLConnection.HTTP_UNAUTHORIZED;

            if (!retVal) {
                LOG.info("Got a non-401 HTTP response code of: " + responseCode);
            }

        } catch (MalformedURLException e) {
            LOG.warn("URL string of '" + urlString + "' is not a valid URL.", e);
            retVal = false;
        } catch (SSLHandshakeException e) {
            LOG.warn("Certificate Error encountered while trying to find the response code.", e);
            retVal = false;
        } catch (IOException e) {
            LOG.warn("IOException encountered while trying to find the response code: " + e.getMessage(), e);
            retVal = false;
        }

        LOG.info("Return value will be " + retVal);

        return retVal;
    }

    @Override
    public boolean hasXSeraphLoginReason(String urlString, String username, String password) {
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return false;
        }

        try {
            HttpURLConnection httpConnection;

            if (proxyService == null) {
                httpConnection = (HttpURLConnection) url.openConnection();
            } else {
                httpConnection = proxyService.getConnectionWithProxyConfig(url, classToProxy);
            }

            setupAuthorization(httpConnection, username, password);

            httpConnection.addRequestProperty("Content-Type", "application/json");
            httpConnection.addRequestProperty("Accept", "application/json");

            String headerResult = httpConnection.getHeaderField("X-Seraph-LoginReason");

            return headerResult != null && headerResult.equals("AUTHENTICATION_DENIED");
        } catch (IOException e) {
            LOG.warn("IOException encountered while trying to find the response code.", e);
        }
        return false;
    }

}
