////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.net.ssl.SSLHandshakeException;
import java.io.*;
import java.net.*;

/**
 * This class holds code for more easily interacting with HTTP-authenticated REST services.
 * So far this is just JIRA but this code could be useful in other places too.
 * 
 * TODO further genericize and move to threadfix common code
 * @author mcollins
 *
 */
public class RestUtilsImpl implements RestUtils {
    private static boolean WRITE_REQUESTS_TO_FILE = true;

	private RestUtilsImpl() {} // intentional, we shouldn't be instantiating this class.
	
	private static final SanitizedLogger LOG = new SanitizedLogger(RestUtilsImpl.class);
    private String postErrorResponse;

    private static RestUtilsImpl INSTANCE = new RestUtilsImpl();

    public static RestUtilsImpl getInstance() {
        return INSTANCE;
    }

	//The following methods help with REST interfaces.
	private InputStream getUrl(String urlString, String username, String password) {
		URL url;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
		HttpURLConnection httpConnection;
		try {
			httpConnection = (HttpURLConnection) url.openConnection();

			setupAuthorization(httpConnection, username, password);
			
			httpConnection.addRequestProperty("Content-Type", "application/json");
			httpConnection.addRequestProperty("Accept", "application/json");

			InputStream stream = httpConnection.getInputStream();

            if (WRITE_REQUESTS_TO_FILE) {
                String responseString = IOUtils.toString(stream);
                OutputStream out = new FileOutputStream(new File("/Users/mac/scratch/" + System.currentTimeMillis()));
                IOUtils.write(urlString + "\n", out);
                IOUtils.write(responseString, out);
                stream = new ByteArrayInputStream(responseString.getBytes());
            }

            return stream;
		} catch (IOException e) {
            LOG.info("Encountered IOException", e);
		    return null;
		}
	}
	
	public String getUrlAsString(String urlString, String username, String password) {
		InputStream responseStream = getUrl(urlString,username,password);
		
		if (responseStream == null) {
			return null;
		}
		
		String test = null;
		try {
			test = IOUtils.toString(responseStream);
		} catch (IOException e) {
			e.printStackTrace();
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

    private InputStream postUrl(String urlString, String data, String username, String password, String contentType) {
		URL url = null;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			LOG.warn("URL used for POST was bad: '" + urlString + "'");
			return null;
		}
		
		HttpURLConnection httpConnection = null;
		OutputStreamWriter outputWriter = null;
		try {
			httpConnection = (HttpURLConnection) url.openConnection();

			setupAuthorization(httpConnection, username, password);
			
			httpConnection.addRequestProperty("Content-Type", contentType);
			httpConnection.addRequestProperty("Accept", contentType);
			
			httpConnection.setDoOutput(true);
			outputWriter = new OutputStreamWriter(httpConnection.getOutputStream());
		    outputWriter.write(data);
		    outputWriter.flush();

			InputStream is = httpConnection.getInputStream();

            if (WRITE_REQUESTS_TO_FILE) {
                String responseString = IOUtils.toString(is);
                OutputStream out = new FileOutputStream(new File("/Users/mac/scratch/" + System.currentTimeMillis()));
                IOUtils.write(urlString + "\n", out);
                IOUtils.write(responseString, out);
                is = new ByteArrayInputStream(responseString.getBytes());
            }
			
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
					}
				} catch (IOException e2) {
					LOG.warn("IOException encountered trying to read the reason for the previous IOException: "
                            + e2.getMessage(), e2);
				}
			}
		} finally {
			if (outputWriter != null) {
				try {
					outputWriter.close();
				} catch (IOException e) {
					LOG.warn("Failed to close output stream in postUrl.", e);
				}
			}
		}
		
		return null;
	}
	
	public String postUrlAsString(String urlString, String data, String username, String password, String contentType) {
		InputStream responseStream = postUrl(urlString,data,username,password, contentType);
		
		if (responseStream == null) {
			return null;
		}
		
		String test = null;
		try {
            test = IOUtils.toString(responseStream);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			closeInputStream(responseStream);
		}
		
		return test;
	}
	
	private void setupAuthorization(HttpURLConnection connection,
			String username, String password) {
		String login = username + ":" + password;
		String encodedLogin = new String(Base64.encodeBase64(login.getBytes()));
		//String encodedLogin = Base64.encodeBase64String(login.getBytes());
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

        CloseableHttpClient httpClient = null;
        try {

            httpClient = HttpClients.custom().build();

            HttpGet httpGet = new HttpGet(urlString);

            HttpResponse response = httpClient.execute(httpGet);

            if (WRITE_REQUESTS_TO_FILE) {
                String responseString = IOUtils.toString(response.getEntity().getContent());
                IOUtils.write(responseString, new FileOutputStream(new File("/Users/mac/scratch/401error" + System.currentTimeMillis())));
            }

            int statusCode = response.getStatusLine().getStatusCode();

            retVal = statusCode == HttpURLConnection.HTTP_UNAUTHORIZED;

            if (!retVal) {
                LOG.info("Got a non-401 HTTP response code of: " + statusCode);
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
        } finally {
            if (httpClient != null) {
                try {
                    httpClient.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        LOG.info("Return value will be " + retVal);

        return retVal;
    }

    @Override
    public boolean hasXSeraphLoginReason(String urlString, String username, String password) {
        URL url;
        try {
            url = new URL(urlString);//getUrlWithRest() + "user?username=" + getUsername());
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return false;
        }

        try {
            HttpURLConnection httpConnection = (HttpURLConnection) url.openConnection();

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
