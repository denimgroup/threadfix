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

import org.h2.util.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Created by mac on 6/3/14.
 */
public class WhiteHatMockHttpUtils implements RemoteProviderHttpUtils {

    public static final String GOOD_API_KEY = "153473b2-5448-4b8d-b8ec-c70a9f4f13cf",
        BAD_API_KEY = "ANY_OTHER_INPUT",
        SITE_PREFIX = "https://sentinel.whitehatsec.com/api/site/?key=" + GOOD_API_KEY,
        SCAN_PREFIX = "https://sentinel.whitehatsec.com/api/vuln/?key=" + GOOD_API_KEY + "&display_attack_vectors=1&query_site=";

    @Override
    public HttpResponse getUrl(String url) {
        if (url.equals(SITE_PREFIX)) {
            return HttpResponse.success(200, getStream("whitehat/apps.xml"));
        } else if (url.startsWith(SCAN_PREFIX)) {
            String appName = url.substring(SCAN_PREFIX.length());
            return HttpResponse.success(200, getStream("whitehat/" + appName + ".xml"));
        } else {
            return HttpResponse.failure();
        }
    }

    private InputStream getStream(String name) {
        InputStream stream = WhiteHatMockHttpUtils.class.getClassLoader().getResourceAsStream(name);

        try {
            return new ByteArrayInputStream(IOUtils.readBytesAndClose(stream, -1));
        } catch (IOException e) {
            e.printStackTrace();
            throw new IllegalStateException("Unable to properly load state.");
        }
    }

    @Override
    public HttpResponse getUrl(String url, String username, String password) {
        return null;
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
        return null;
    }

    @Override
    public HttpResponse postUrl(String url, String[] parameters, String[] values, String username, String password, String[] headerNames, String[] headerVals) {
        return null;
    }
}
