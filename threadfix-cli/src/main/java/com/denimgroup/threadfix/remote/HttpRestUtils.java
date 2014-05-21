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
package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.properties.PropertiesManager;
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
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;

public class HttpRestUtils {

    public static final String API_KEY_SEGMENT = "?apiKey=";

    @NotNull
    final PropertiesManager propertiesManager;

    private static final SanitizedLogger LOGGER = new SanitizedLogger(HttpRestUtils.class);

    public HttpRestUtils(@NotNull PropertiesManager manager) {
        this.propertiesManager = manager;
    }

    @NotNull
	public <T> RestResponse<T> httpPostFile(@NotNull String path,
                                            @NotNull File file,
                                            @NotNull String[] paramNames,
                                            @NotNull String[] paramVals,
                                            @NotNull Class<T> targetClass) {

		//	TODO - Revisit how we handle certificate errors here
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

        String completeUrl = makePostUrl(path);

		PostMethod filePost = new PostMethod(completeUrl);

		filePost.setRequestHeader("Accept", "application/json");

        RestResponse<T> response;
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

            response = ResponseParser.getRestResponse(filePost.getResponseBodyAsStream(), status, targetClass);

        } catch (IOException e1) {
            LOGGER.error("There was an error and the POST request was not finished.", e1);
            response = ResponseParser.getErrorResponse(
                    "There was an error and the POST request was not finished.",
                    status);
        }

        return response;
    }

    @NotNull
    public <T> RestResponse<T> httpPost(@NotNull String path,
                                        @NotNull String[] paramNames,
                                        @NotNull String[] paramVals,
                                        @NotNull Class<T> targetClass) {

		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

        String urlString = makePostUrl(path);

		PostMethod post = new PostMethod(urlString);

		post.setRequestHeader("Accept", "application/json");

        int responseCode = -1;
        RestResponse<T> response;

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

            response = ResponseParser.getRestResponse(post.getResponseBodyAsStream(), responseCode, targetClass);

		} catch (IOException e1) {
            LOGGER.error("Encountered IOException while trying to post to " + path, e1);
            response = ResponseParser.getErrorResponse(
                    "There was an error and the POST request was not finished.",
                    responseCode);
		}

        return response;
	}

    @NotNull
    public <T> RestResponse<T> httpGet(@NotNull String path, @NotNull Class<T> targetClass) {
        return httpGet(path, "", targetClass);
    }

    @NotNull
	public <T> RestResponse<T> httpGet(@NotNull String path, @NotNull String params,
                                       @NotNull Class<T> targetClass) {

        String urlString = makeGetUrl(path, params);

		LOGGER.debug("Requesting " + urlString);

		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));
		GetMethod get = new GetMethod(urlString);

		get.setRequestHeader("Accept", "application/json");

		HttpClient client = new HttpClient();

        int status = -1;
        RestResponse<T> response;

		try {
			status = client.executeMethod(get);

			if (status != 200) {
                LOGGER.error("Status was not 200. It was " + status);
			}

            response = ResponseParser.getRestResponse(get.getResponseBodyAsStream(), status, targetClass);

		} catch (IOException e) {
            LOGGER.error("Encountered IOException while trying to post to " + path, e);
            response = ResponseParser.getErrorResponse("There was an error and the GET request was not finished.", status);
		}

		return response;
	}

    @NotNull
    private String makeGetUrl(@NotNull String path, @NotNull String params) {
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

    @NotNull
    private String makePostUrl(@NotNull String path) {
        String baseUrl = propertiesManager.getUrl();

        LOGGER.debug("Building POST url with path " + path + " and base url " + baseUrl);

        if (baseUrl.endsWith("/rest") && path.charAt(0) != '/') {
            baseUrl = baseUrl + "/";
        }

        LOGGER.debug("Returning " + baseUrl + path);

        return baseUrl + path;
    }

    private void addApiKey(PostMethod post) {
        post.addParameter("apiKey", propertiesManager.getKey());
    }
}