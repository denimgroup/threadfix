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
package com.denimgroup.threadfix.service.defects;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.denimgroup.threadfix.service.SanitizedLogger;

/**
 * This class holds code for more easily interacting with HTTP-authenticated REST services.
 * So far this is just JIRA but this code could be useful in other places too.
 * 
 * TODO further genericize and move to threadfix common code
 * @author mcollins
 *
 */
public class RestUtils {
	
	private RestUtils() {} // intentional, we shouldn't be instantiating this class.
	
	private static final SanitizedLogger log = new SanitizedLogger(RestUtils.class);
	
	//The following methods help with REST interfaces.
	public static InputStream getUrl(String urlString, String username, String password) {
		URL url = null;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
		InputStream is = null;
		HttpURLConnection httpConnection;
		try {
			httpConnection = (HttpURLConnection) url.openConnection();

			setupAuthorization(httpConnection, username, password);
			
			httpConnection.addRequestProperty("Content-Type", "application/json");
			httpConnection.addRequestProperty("Accept", "application/json");

			is = httpConnection.getInputStream();
			
			return is;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return is;
	}
	
	public static String getUrlAsString(String urlString, String username, String password) {
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
	
	public static void closeInputStream(InputStream stream) {
		if (stream != null) {
			try {
				stream.close();
			} catch (IOException ex) {
				log.warn("Closing an input stream failed.", ex);
			}
		}
	}
	
	public static InputStream postUrl(String urlString, String data, String username, String password) {
		URL url = null;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			log.warn("URL used for POST was bad: '" + urlString + "'");
			return null;
		}
		
		HttpURLConnection httpConnection = null;
		OutputStreamWriter outputWriter = null;
		try {
			httpConnection = (HttpURLConnection) url.openConnection();

			setupAuthorization(httpConnection, username, password);
			
			httpConnection.addRequestProperty("Content-Type", "application/json");
			httpConnection.addRequestProperty("Accept", "application/json");
			
			httpConnection.setDoOutput(true);
			outputWriter = new OutputStreamWriter(httpConnection.getOutputStream());
		    outputWriter.write(data);
		    outputWriter.flush();

			InputStream is = httpConnection.getInputStream();
			
			return is;
		} catch (IOException e) {
			log.warn("IOException encountered trying to post to URL with message: " + e.getMessage());
			if(httpConnection == null) {
				log.warn("HTTP connection was null so we cannot do further debugging of why the HTTP request failed");
			} else {
				try {
					InputStream errorStream = httpConnection.getErrorStream();
					if(errorStream == null) {
						log.warn("Error stream from HTTP connection was null");
					} else {
						log.warn("Error stream from HTTP connection was not null. Attempting to get response text.");
						String postErrorResponse = IOUtils.toString(errorStream);
						log.warn("Error text in response was '" + postErrorResponse + "'");
					}
				} catch (IOException e2) {
					log.warn("IOException encountered trying to read the reason for the previous IOException: "
								+ e2.getMessage(), e2);
				}
			}
		} finally {
			if (outputWriter != null) {
				try {
					outputWriter.close();
				} catch (IOException e) {
					log.warn("Failed to close output stream in postUrl.", e);
				}
			}
		}
		
		return null;
	}
	
	public static String postUrlAsString(String urlString, String data, String username, String password) {
		InputStream responseStream = postUrl(urlString,data,username,password);
		
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
	
	public static void setupAuthorization(HttpURLConnection connection,
			String username, String password) {
		String login = username + ":" + password;
		String encodedLogin = new String(Base64.encodeBase64(login.getBytes()));
		//String encodedLogin = Base64.encodeBase64String(login.getBytes());
		connection.setRequestProperty("Authorization", "Basic " + encodedLogin);
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * TODO validate to save generating an exception on invalid input
	 * @param responseContents
	 * @return
	 */
	public static JSONArray getJSONArray(String responseContents) {
		try {
			return new JSONArray(responseContents);
		} catch (JSONException e) {
			log.warn("JSON Parsing failed.", e);
			return null;
		}
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * TODO validate to save generating an exception on invalid input
	 * @param responseContents
	 * @return
	 */
	public static JSONObject getJSONObject(String responseContents) {
		try {
			return new JSONObject(responseContents);
		} catch (JSONException e) {
			log.warn("JSON Parsing failed.", e);
			return null;
		}
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * TODO validate to save generating an exception on invalid input
	 * @param object
	 * @return
	 */
	public static Integer getId(JSONObject object) {
		try {
			return object.getInt("id");
		} catch (JSONException e) {
			log.warn("Failed when trying to parse an ID out of the object.", e);
			return null;
		}
	}
}
