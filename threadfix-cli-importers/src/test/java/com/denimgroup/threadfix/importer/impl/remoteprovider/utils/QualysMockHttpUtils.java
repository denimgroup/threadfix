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
package com.denimgroup.threadfix.importer.impl.remoteprovider.utils;

import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.importer.impl.remoteprovider.QualysRemoteProvider;

import java.io.InputStream;

/**
 * Created by mac on 6/3/14.
 */
public class QualysMockHttpUtils implements RemoteProviderHttpUtils {

    public static final RemoteProviderType type = new RemoteProviderType();

    public static final String GOOD_USERNAME = "user",
            BAD_USERNAME = "bad username",
            GOOD_PASSWORD = "password",
            BAD_PASSWORD = "bad password",
            SCAN_SEARCH_URL = QualysRemoteProvider.getScansForAppUrl(type),
            SPECIFIC_SCAN_URL = QualysRemoteProvider.getScanUrl(type),
            APPS_URL = QualysRemoteProvider.getAppsUrl(type);


    @Override
    public HttpResponse getUrl(String url) {
        return null;
    }

    private InputStream getStream(String name) {
        InputStream stream = QualysMockHttpUtils.class.getClassLoader().getResourceAsStream(name);
        assert stream != null : "Failed to retrieve resource " + name;
        return stream;
    }

    @Override
    public HttpResponse getUrl(String url, String username, String password) {

        assert username != null : "Username was null. This should never happen.";
        assert password != null : "Password was null. This should never happen.";

        if (username.equals(GOOD_USERNAME) && password.equals(GOOD_PASSWORD)) {
            if (url.startsWith(SPECIFIC_SCAN_URL)) {

                String appId = url.substring(SPECIFIC_SCAN_URL.length());

                if (appId.equals("5622189")) {
                    return HttpResponse.success(200, getStream("qualys/testasp.xml"));
                } else if (appId.equals("5622196")) {
                    return HttpResponse.success(200, getStream("qualys/testphp.xml"));
                }
            }
        } else {
            return HttpResponse.failure(403);
        }

        return HttpResponse.failure();
    }

    @Override
    public HttpResponse getUrlWithConfigurer(String url, RequestConfigurer configurer) {
        return getUrl(url);
    }

    @Override
    public HttpResponse postUrl(String url, String[] parameters, String[] values) {
        return null;
    }

    @Override
    public HttpResponse postUrl(String url, String[] parameters, String[] values, String username, String password) {
        assert username != null : "Username was null. This should never happen.";
        assert password != null : "Password was null. This should never happen.";

        if (username.equals(GOOD_USERNAME) && password.equals(GOOD_PASSWORD)) {
            if (url.equals(APPS_URL)) {
                return HttpResponse.success(200, getStream("qualys/apps-authenticated.xml"));
            } else if (url.equals(SCAN_SEARCH_URL)) {
                return HttpResponse.success(200, getStream("qualys/scans.xml"));
            }
        } else {
            return HttpResponse.failure(403);
        }

        return HttpResponse.failure();
    }

    @Override
    public HttpResponse postUrl(String url, String[] parameters, String[] values, String username, String password, String[] headerNames, String[] headerVals) {
        return postUrl(url, parameters, values, username, password);
    }
}
