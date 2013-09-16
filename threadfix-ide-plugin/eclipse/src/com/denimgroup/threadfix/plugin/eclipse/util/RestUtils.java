package com.denimgroup.threadfix.plugin.eclipse.util;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.io.IOUtils;


public class RestUtils {
	
	public RestUtils(String key, String url) {
		this.key = key;
		if (url == null) {
			this.url = "http://localhost:8080/threadfix/rest";
		} else {
			this.url = url;
		}
	}
	
	private final String key, url;
	
	public String getMarkers(String appId) {
		String result = httpGet(url + "/code/markers/" + appId +
				"?apiKey=" + key);
		
		return result;
	}
	
	public String httpGet(String urlStr) {
		
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
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return "There was an error and the GET request was not finished.";
	}
}
