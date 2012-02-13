package com.denimgroup.threadfix.webservices.tests;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.apache.commons.httpclient.methods.multipart.StringPart;
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
	
	protected final Log log = LogFactory.getLog(BaseRestTest.class);
	
	public static final String GOOD_API_KEY = "QRUusnkGqKE6zAlGwsFVHcxPWW8qlfPpwcaLmXBo6gCA";
	public static final String BAD_API_KEY = "QRUusnkGqKE6zAlGwsFVHcxPWW3qlfPpwcaLmXBo6gCA";
	public static final String BASE_URL = "http://satoffice043:8080/threadfix/rest/";

	public String httpPostFile(String request, String fileName, String[] paramNames,
			String[] paramVals) {
		File file = new File(fileName);
		return httpPostFile(request, file, paramNames,
				paramVals);
	}
	
	public String httpPostFile(String request, File file, String[] paramNames,
			String[] paramVals) {

		PostMethod filePost = new PostMethod(request);
		
		filePost.setRequestHeader("Accept", "application/json");
		
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
				System.err.println("Status was not 200.");
			}
			
			InputStream responseStream = filePost.getResponseBodyAsStream();
			
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

	public String httpPost(String request, String[] paramNames,
			String[] paramVals) {

		PostMethod post = new PostMethod(request);
		
		post.setRequestHeader("Accept", "application/json");
		
		try {
			for (int i = 0; i < paramNames.length; i++) {
				post.addParameter(paramNames[i], paramVals[i]);
			}
			
			HttpClient client = new HttpClient();
			int status = client.executeMethod(post);
			if (status != 200) {
				System.err.println("Status was not 200.");
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
		GetMethod get = new GetMethod(urlStr);
		
		get.setRequestHeader("Accept", "application/json");
		
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
}
