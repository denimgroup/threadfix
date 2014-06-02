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
package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ProxyService;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;

/**
 * Created by mac on 6/2/14.
 */
public class RemoteProviderHttpUtilsImpl<T> extends SpringBeanAutowiringSupport implements RemoteProviderHttpUtils {

    private static final SanitizedLogger LOG = new SanitizedLogger(RemoteProviderHttpUtils.class);

    private final Class<T> classInstance;
    private HttpClient HttpClientInstance = null;
    @Autowired(required = false)
    private ProxyService proxyService;

    public RemoteProviderHttpUtilsImpl(Class<T> targetClass) {
        assert targetClass != null;
        classInstance = targetClass;
    }

    @Override
    public HttpResponse getUrl(String url) {
        return getUrl(url, null, null);
    }

    @Override
    @NotNull
    public HttpResponse getUrl(String url, String username, String password) {

        assert url != null;

        GetMethod get = new GetMethod(url);

        get.setRequestHeader("Content-type", "text/xml; charset=UTF-8");

        if (username != null && password != null) {
            String login = username + ":" + password;
            String encodedLogin = new String(Base64.encodeBase64(login.getBytes()));

            get.setRequestHeader("Authorization", "Basic " + encodedLogin);
        }

        HttpClient client = getConfiguredHttpClient(classInstance);
        try {
            int status = client.executeMethod(get);

            if (status == 200) {
                InputStream responseStream = get.getResponseBodyAsStream();
                return HttpResponse.success(status, responseStream);
            } else {
                LOG.warn("Status : " + status);
            }
        } catch (IOException e) {
            LOG.error("Encountered IOException while making request in " + classInstance.getName() + ".", e);
        }
        return HttpResponse.failure();
    }

    @Override
    public HttpResponse postUrl(String url, String[] paramNames, String[] paramVals) {
        return postUrl(url, paramNames, paramVals, null, null);
    }

    @Override
    public HttpResponse postUrl(String url, String[] paramNames, String[] paramVals, String username, String password) {
        assert url != null;

        PostMethod post = new PostMethod(url);

        post.setRequestHeader("Content-type", "text/xml; charset=UTF-8");

        if (username != null && password != null) {
            String login = username + ":" + password;
            String encodedLogin = new String(Base64.encodeBase64(login.getBytes()));

            post.setRequestHeader("Authorization", "Basic " + encodedLogin);
        }

        try {
            for (int i = 0; i < paramNames.length; i++) {
                post.addParameter(paramNames[i], paramVals[i]);
            }

            HttpClient client = getConfiguredHttpClient(QualysRemoteProvider.class);

            int status = client.executeMethod(post);

            if (status == 200) {
                InputStream responseStream = post.getResponseBodyAsStream();
                return HttpResponse.success(status, responseStream);
            } else {
                LOG.warn("Status : " + status);
                return HttpResponse.failure(status);
            }

        } catch (IOException e1) {
            LOG.error("Encountered IOException while making request to Veracode.", e1);
        }

        LOG.warn("There was an error and the POST request was not finished.");
        return HttpResponse.failure();
    }

    protected <T> HttpClient getConfiguredHttpClient(Class<T> classToProxy) {
        if (HttpClientInstance == null) {
            if (proxyService == null) {
                HttpClientInstance = new HttpClient();
            } else {
                HttpClientInstance = proxyService.getClientWithProxyConfig(classToProxy);
            }
        }

        assert HttpClientInstance != null;

        return HttpClientInstance;
    }
}
