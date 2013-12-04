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
package com.denimgroup.threadfix.plugins.intellij.rest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.denimgroup.threadfix.plugins.intellij.properties.PropertiesManager;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;


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
		return new RestUtils(PropertiesManager.getApiKey(), PropertiesManager.getUrl());
	}
	
	public String getMarkers(String appId) {
		return httpGet(url + "/code/markers/" + appId +
				"?apiKey=" + key);
	}

	public String getApplications() {
		String result = httpGet(url + "/code/applications/?apiKey=" + key);
		if(result.contains("<html lang=\"en\">")){
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
				return getString(responseStream);
			}
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return "There was an error and the GET request was not finished.";
	}

    private String getString(InputStream stream) {
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(stream));
            String line;

            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append('\n');
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return stringBuilder.toString();
    }

}
