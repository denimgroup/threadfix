////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.plugin.zap;

//import com.denimgroup.threadfix.data.interfaces.Endpoint;
//import com.denimgroup.threadfix.plugin.zap.action.LocalEndpointsAction;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.plugin.zap.action.ImportAction;
import com.denimgroup.threadfix.plugin.zap.action.LocalEndpointsAction;
import com.denimgroup.threadfix.plugin.zap.action.RemoteEndpointsAction;
import com.denimgroup.threadfix.remote.PluginClient;
import com.denimgroup.threadfix.remote.response.RestResponse;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.log4j.Logger;
//import org.zaproxy.zap.extension.api.ApiImplementor;
//import org.zaproxy.zap.extension.api.*;
import org.zaproxy.zap.extension.api.*;
import org.zaproxy.zap.extension.threadfix.ThreadFixExtension;
import org.zaproxy.zap.extension.threadfix.ZapApiPropertiesManager;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by dshannon on 2/23/15.
 */
public class ThreadFixApi extends ApiImplementor {
    private static final String LIST_THREADFIX_APPLICATIONS = "listThreadFixApplications";
    private static final String IMPORT_ENDPOINTS_FROM_THREADFIX = "importEndpointsFromThreadFix";
    private static final String EXPORT_SCAN = "exportScan";
    private static final String IMPORT_ENDPOINTS_FROM_SOURCE = "importEndpointsFromSource";

    private static final String PARAM_THREAD_FIX_URL = "threadFixUrl";
    private static final String PARAM_API_KEY = "apiKey";
    private static final String PARAM_APP_ID = "appId";
    private static final String PARAM_TARGET_URL = "targetUrl";
    private static final String PARAM_SOURCE_FOLDER = "sourceFolder";

    ThreadFixExtension threadFixExtension;

    private static final Logger logger = Logger.getLogger(ThreadFixExtension.class);

    public ThreadFixApi(ThreadFixExtension threadFixExtension) {
        super();
        this.threadFixExtension = threadFixExtension;

        this.addApiView(new ApiView(LIST_THREADFIX_APPLICATIONS, new String[]{PARAM_THREAD_FIX_URL, PARAM_API_KEY}));

        this.addApiAction(new ApiAction(IMPORT_ENDPOINTS_FROM_THREADFIX, new String[]{PARAM_THREAD_FIX_URL, PARAM_API_KEY, PARAM_APP_ID, PARAM_TARGET_URL}));
        this.addApiAction(new ApiAction(EXPORT_SCAN, new String[]{PARAM_THREAD_FIX_URL, PARAM_API_KEY, PARAM_APP_ID}));
        this.addApiAction(new ApiAction(IMPORT_ENDPOINTS_FROM_SOURCE, new String[]{PARAM_SOURCE_FOLDER, PARAM_TARGET_URL}));
    }

    @Override
    public String getPrefix() {
        return "threadFix";
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        logger.info("Request for handleApiView: " + name + " (params: " + params.toString() + ")");

        ZapApiPropertiesManager zapApiPropertiesManager;
        switch (name) {
            case LIST_THREADFIX_APPLICATIONS:
                logger.info(LIST_THREADFIX_APPLICATIONS);
                String threadFixUrl = getThreadFixUrl(params);
                String apiKey = getApiKey(params);
                zapApiPropertiesManager = new ZapApiPropertiesManager(threadFixUrl, apiKey);
                PluginClient client = new PluginClient(zapApiPropertiesManager);

                RestResponse<Application.Info[]> response = client.getThreadFixApplicationsResponse();
                if (response.success) {
                    Application.Info[] apps = response.object;
                    ApiResponseList applicationList = new ApiResponseList("applications");
                    if (apps != null) {
                        for (Application.Info app : apps) {
                            if (app != null) {
                                String appCombinedName = app.getOrganizationName() + "/" + app.getApplicationName();
                                String appId = app.getApplicationId();
                                if (appCombinedName != null && appId != null) {
                                    Map<String, String> appValues = new HashMap<String, String>(2);
                                    appValues.put("name", appCombinedName);
                                    appValues.put("id", appId);
                                    ApiResponseSet appElement = new ApiResponseSet("application", appValues);
                                    applicationList.addItem(appElement);
                                }
                            }
                        }
                    }
                    return applicationList;
                } else {
                    throwFailedResponseApiException(response, "code/applications");
                }
        }
        throw new ApiException(ApiException.Type.BAD_VIEW, name);
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        logger.info("Request for handleApiAction: " + name + " (params: " + params.toString() + ")");

        ZapApiPropertiesManager zapApiPropertiesManager;
        String threadFixUrl;
        String apiKey;
        String appId;
        String targetUrl;

        switch (name) {
            case IMPORT_ENDPOINTS_FROM_THREADFIX:
                logger.info(IMPORT_ENDPOINTS_FROM_SOURCE);
                RemoteEndpointsAction remoteEndpointsAction = threadFixExtension.getRemoteEndpointsAction();

                threadFixUrl = getThreadFixUrl(params);
                apiKey = getApiKey(params);
                appId = String.valueOf(getAppId(params));
                targetUrl = getTargetUrl(params);
                zapApiPropertiesManager = new ZapApiPropertiesManager(threadFixUrl, apiKey, appId);

                RestResponse<Endpoint.Info[]> endpointsResponse = remoteEndpointsAction.getEndpointsResponse(zapApiPropertiesManager);
                if (endpointsResponse.success) {
                    Endpoint.Info[] endpoints = endpointsResponse.object;
                    remoteEndpointsAction.buildNodesFromEndpoints(endpoints);
                    remoteEndpointsAction.attackUrl(targetUrl);
                    return ApiResponseElement.OK;
                } else {
                    throwFailedResponseApiException(endpointsResponse, "code/applications/" + appId + "/endpoints");
                }
            case EXPORT_SCAN:
                logger.info(EXPORT_SCAN);
                ImportAction importAction = threadFixExtension.getImportAction();

                threadFixUrl = getThreadFixUrl(params);
                apiKey = getApiKey(params);
                appId = String.valueOf(getAppId(params));
                zapApiPropertiesManager = new ZapApiPropertiesManager(threadFixUrl, apiKey, appId);

                RestResponse<Object> uploadResponse = importAction.uploadReportAndGetResponse(zapApiPropertiesManager);
                if ((uploadResponse != null) && (uploadResponse.success)) {
                    return ApiResponseElement.OK;
                } else {
                    throwFailedResponseApiException(uploadResponse, "applications/" + appId + "/upload");
                }
            case IMPORT_ENDPOINTS_FROM_SOURCE:
                logger.info(IMPORT_ENDPOINTS_FROM_SOURCE);
                LocalEndpointsAction localEndpointsAction = threadFixExtension.getLocalEndpointsAction();
                Endpoint.Info[] endpoints;
                try {
                    endpoints = localEndpointsAction.getEndpoints(String.valueOf(params.get(PARAM_SOURCE_FOLDER)));
                } catch (Exception e) {
                    endpoints = null;
                }
                if ((endpoints != null) && (endpoints.length > 0)) {
                    localEndpointsAction.buildNodesFromEndpoints(endpoints);
                    localEndpointsAction.attackUrl(String.valueOf(params.get(PARAM_TARGET_URL)));
                    return ApiResponseElement.OK;
                } else {
                    throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Unable to generate endpoints from source. Please check the file path.");
                }
        }
        throw new ApiException(ApiException.Type.BAD_ACTION, name);
    }

    private <T> void throwFailedResponseApiException(RestResponse<T> response, String path) throws ApiException {
        throwFailedResponseApiException(response, path, ApiException.Type.INTERNAL_ERROR);
    }

    private <T> void throwFailedResponseApiException(RestResponse<T> response, String path, ApiException.Type exceptionType) throws ApiException {
        int responseCode = response.responseCode;
        String message = response.message;

        StringBuilder errorMessage = new StringBuilder();
        errorMessage.append("Request for ThreadFix data failed at ");
        errorMessage.append(path);
        errorMessage.append(". Response Code: ");
        errorMessage.append(responseCode);
        if ((message != null) && (message.length() > 0)) {
            errorMessage.append(" Message: ");
            errorMessage.append(message);
        }

        throw new ApiException(exceptionType, errorMessage.toString());
    }

    /**
     * Gets the ThreadFix URL from the parameters or throws a Missing Parameter exception, if any
     * problems occured.
     *
     * @param params the params
     * @return the ThreadFix URL
     * @throws ApiException the api exception
     */
    private String getThreadFixUrl(JSONObject params) throws ApiException {
        try {
            return params.getString(PARAM_THREAD_FIX_URL);
        } catch (JSONException ex) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_THREAD_FIX_URL);
        }
    }

    /**
     * Gets the ThreadFix API key from the parameters or throws a Missing Parameter exception, if any
     * problems occured.
     *
     * @param params the params
     * @return the API key
     * @throws ApiException the api exception
     */
    private String getApiKey(JSONObject params) throws ApiException {
        try {
            return params.getString(PARAM_API_KEY);
        } catch (JSONException ex) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_API_KEY);
        }
    }

    /**
     * Gets the ThreadFix application id from the parameters or throws a Missing Parameter exception, if any
     * problems occured.
     *
     * @param params the params
     * @return the application id
     * @throws ApiException the api exception
     */
    private int getAppId(JSONObject params) throws ApiException {
        try {
            return params.getInt(PARAM_APP_ID);
        } catch (JSONException ex) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_APP_ID);
        }
    }

    /**
     * Gets the target URL from the parameters or throws a Missing Parameter exception, if any
     * problems occured.
     *
     * @param params the params
     * @return the target URL
     * @throws ApiException the api exception
     */
    private String getTargetUrl(JSONObject params) throws ApiException {
        try {
            return params.getString(PARAM_TARGET_URL);
        } catch (JSONException ex) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_TARGET_URL);
        }
    }

    /**
     * Gets the source folder from the parameters or throws a Missing Parameter exception, if any
     * problems occured.
     *
     * @param params the params
     * @return the source folder
     * @throws ApiException the api exception
     */
    private String getSourceFolder(JSONObject params) throws ApiException {
        try {
            return params.getString(PARAM_SOURCE_FOLDER);
        } catch (JSONException ex) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_SOURCE_FOLDER);
        }
    }
}
