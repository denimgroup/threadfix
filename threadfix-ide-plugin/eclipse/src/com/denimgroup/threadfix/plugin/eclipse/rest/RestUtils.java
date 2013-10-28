package com.denimgroup.threadfix.plugin.eclipse.rest;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.io.IOUtils;

import com.denimgroup.threadfix.plugin.eclipse.util.SettingsUtils;


public class RestUtils {
	
	private RestUtils(String key, String url) {
		this.key = key;
		if (url == null || url.trim().isEmpty()) {
			this.url = "http://localhost:8080/threadfix/rest";
		} else {
			this.url = url;
		}
	}
	
	private final String key, url;
	
	public static RestUtils getFromSettings() {
		return new RestUtils(SettingsUtils.getApiKey(), SettingsUtils.getUrl());
	}
	
	public String getMarkers(String appId) {
		String result = httpGet(url + "/code/markers/" + appId +
				"?apiKey=" + key);
		
		return result;
	}

	public String getApplications() {
		String result = httpGet(url + "/code/applications/?apiKey=" + key);
		if(result.contains("html")){
			return "Authentication failed,check rest url";
		}
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
				System.out.println("Status was not 200.");
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
