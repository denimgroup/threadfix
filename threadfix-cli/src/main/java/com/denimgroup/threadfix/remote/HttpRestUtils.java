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
package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.remote.response.AbstractRestResponse;
import com.denimgroup.threadfix.remote.response.ResponseParser;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.apache.commons.httpclient.methods.multipart.StringPart;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public class HttpRestUtils {

    private HttpRestUtils(){}

	public static String httpPostFile(String request, String fileName, String[] paramNames, String[] paramVals) {
		File file = new File(fileName);
		return httpPostFile(request, file, paramNames,
				paramVals);
	}
	
	private static String httpPostFile(String request, File file, String[] paramNames, String[] paramVals) {
		
		//	TODO - Revisit how we handle certificate errors here
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

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
				System.err.println("Request for '" + request + "' status was " + status + ", not 200 as expected.");
			}
			
			InputStream responseStream = filePost.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return IOUtils.toString(responseStream);
			} else {
				System.err.println("Response stream was null");
			}

		} catch (IOException e) {
			e.printStackTrace();
		}

		return "There was an error and the POST request was not finished.";
	}

    public static String httpPost(String urlString,
                           String[] paramNames,
                           String[] paramVals) {

        RestResponse response = httpPost(urlString, paramNames, paramVals, RestResponse.class);

        if (response.success) {
            return response.getObjectAsJsonString();
        } else {
            return response.message;
        }
    }

    public static <T extends AbstractRestResponse> T httpPost(String urlStr,
                                              String[] paramNames,
                                              String[] paramVals,
                                              Class<T> targetClass) {

		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

		PostMethod post = new PostMethod(urlStr);
		
		post.setRequestHeader("Accept", "application/json");

        int responseCode = -1;
        T response;

		try {
			for (int i = 0; i < paramNames.length; i++) {
				if (paramNames[i] != null && paramVals[i] != null) {
					post.addParameter(paramNames[i], paramVals[i]);
				}
			}
			
			HttpClient client = new HttpClient();
			responseCode = client.executeMethod(post);
			if (responseCode != 200) {
				System.err.println("Request for '" + urlStr + "' status was " + responseCode + ", not 200 as expected.");
			}
			
            response = ResponseParser.getRestResponse(post.getResponseBodyAsStream(), responseCode, targetClass);

		} catch (IOException e1) {
			e1.printStackTrace();
            response = ResponseParser.getErrorResponse(
                    "There was an error and the POST request was not finished.",
                    responseCode,
                    targetClass);
		}

        return response;
	}

    public static String httpGet(String urlString) {
        RestResponse response = httpGet(urlString, RestResponse.class);

        if (response.success) {
            return response.getObjectAsJsonString();
        } else {
            return response.message;
        }
    }

	public static <T extends AbstractRestResponse> T httpGet(String urlStr, Class<T> targetClass) {
		
		System.out.println("Requesting " + urlStr);
		
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));
		GetMethod get = new GetMethod(urlStr);
		
		get.setRequestHeader("Accept", "application/json");
		
		HttpClient client = new HttpClient();

        int status = -1;
        T response;

		try {
			status = client.executeMethod(get);

			if (status != 200) {
				System.err.println("Status was not 200.");
			}
			
            response = ResponseParser.getRestResponse(get.getResponseBodyAsStream(), status, targetClass);

		} catch (IOException e) {
			e.printStackTrace();
            response = ResponseParser.getErrorResponse("There was an error and the GET request was not finished.", status, targetClass);
		}

		return response;
	}
	
}
