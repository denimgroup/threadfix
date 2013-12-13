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

import com.denimgroup.threadfix.plugins.intellij.properties.Constants;
import com.denimgroup.threadfix.plugins.intellij.properties.PropertiesManager;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;


public class RestUtils {
	
	private RestUtils(String key, String url) {
		this.key = key;
		if (url == null || url.trim().isEmpty()) {
			this.url = Constants.DEFAULT_URL;
		} else {
			this.url = url;
		}
	}
	
	private final String key, url;
	
	public static RestUtils getFromSettings() {
		return new RestUtils(PropertiesManager.getApiKey(), PropertiesManager.getUrl());
	}

    @Nullable
	public String getMarkers(String appId) {

        RestResponse response = httpGet(url +
                Constants.MARKERS_URL_SEGMENT + appId +
                Constants.API_KEY_QUERY_START + key);

        if (response.status == 200) {
            return response.text;
        } else {
            return null;
        }
	}

    @Nullable
	public String getApplications() {
		RestResponse response = httpGet(url +
                Constants.APPLICATIONS_URL_SEGMENT +
                Constants.API_KEY_QUERY_START + key);
		if(response.status != 200 || response.text.contains("<html lang=\"en\">")){
			return null;
		} else {
		    return response.text;
        }
	}

    // the UI validation should ensure that the /rest part of the returned url is valid.
    public static RestResponse test(String url) {
        return test(url, "test");
    }

    // the UI validation should ensure that the /rest part of the returned url is valid.
    public static RestResponse test(String url, String key) {
        return httpGet(url +
                Constants.MARKERS_URL_SEGMENT + "0" +
                Constants.API_KEY_QUERY_START + key);
    }
	
	private static RestResponse httpGet(String urlStr) {
		
		System.out.println("Requesting " + urlStr);
		
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));
		GetMethod get = new GetMethod(urlStr);
		
		HttpClient client = new HttpClient();
		try {
			int status = client.executeMethod(get);
			if (status != 200) {
				System.out.println("Status was " + status + ", was expecting 200.");
			}
			
			InputStream responseStream = get.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return new RestResponse(getString(responseStream), status);
			}
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return new RestResponse("", -1);
	}

    private static String getString(InputStream stream) {
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
