//////////////////////////////////////////////////////////////////////
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ProxyService;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.annotation.Nonnull;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;

public class RemoteProviderHttpUtilsImpl<T> extends SpringBeanAutowiringSupport implements RemoteProviderHttpUtils {

    private static final SanitizedLogger LOG = new SanitizedLogger(RemoteProviderHttpUtils.class);

    private final Class<T> classInstance;
    private HttpClient httpClientInstance = null;
    @Autowired(required = false)
    private ProxyService proxyService;

    public static <T> RemoteProviderHttpUtilsImpl<T> getImpl(Class<T> targetClass) {
        return new RemoteProviderHttpUtilsImpl<T>(targetClass);
    }

    public RemoteProviderHttpUtilsImpl(Class<T> targetClass) {
        assert targetClass != null;
        classInstance = targetClass;
    }

    @Override
    public HttpResponse getUrl(String url) {
        return getUrl(url, null, null);
    }

    @Override
    @Nonnull
    public HttpResponse getUrl(String url, final String username, final String password) {
        assert url != null;

        return getUrlWithConfigurer(url, new RequestConfigurer() {
            @Override
            public void configure(HttpMethodBase method) {
                if (username != null && password != null) {
                    String login = username + ":" + password;
                    String encodedLogin = DatatypeConverter.printBase64Binary(login.getBytes());
                    method.setRequestHeader("Authorization", "Basic " + encodedLogin);
                }
                method.setRequestHeader("Content-type", "text/xml; charset=UTF-8");
            }
        });
    }

    @Override
    public HttpResponse getUrlWithConfigurer(String url, RequestConfigurer configurer) {
        assert url != null;
        assert configurer != null;

        GetMethod get = new GetMethod(url);

        get.setRequestHeader("Content-type", "text/xml; charset=UTF-8");

        configurer.configure(get);

        HttpClient client = getConfiguredHttpClient(classInstance);

        int status = -1;

        try {
            status = client.executeMethod(get);

            if (status != 200) {
                LOG.warn("Status wasn't 200, it was " + status);
                return HttpResponse.failure(status, get.getResponseBodyAsStream());
            } else {
                return HttpResponse.success(status, get.getResponseBodyAsStream());
            }

        } catch (IOException e) {
            LOG.error("Encountered IOException while making request in " + classInstance.getName() + ".", e);
        }
        return HttpResponse.failure(status);
    }

    @Override
    public HttpResponse postUrl(String url, String[] paramNames, String[] paramVals) {
        return postUrlWithConfigurer(url, new DefaultRequestConfigurer()
                .withPostParameters(paramNames, paramVals));
    }

    @Override
    public HttpResponse postUrl(String url, String[] paramNames, String[] paramVals, String username, String password) {
        return postUrlWithConfigurer(url, new DefaultRequestConfigurer()
                .withPostParameters(paramNames, paramVals)
                .withUsernamePassword(username, password));
    }

    @Override
    public HttpResponse postUrl(String url, String[] paramNames, String[] paramVals, String username, String password, String[] headerNames, String[] headerVals) {
        return postUrlWithConfigurer(url, new DefaultRequestConfigurer()
                .withPostParameters(paramNames, paramVals)
                .withHeaders(headerNames, headerVals)
                .withUsernamePassword(username, password));
    }

    @Override
    public HttpResponse postUrlWithConfigurer(String url, RequestConfigurer requestConfigurer) {
        if (url == null) {
            throw new IllegalArgumentException("Null url passed to postUrlWithConfigurer.");
        }

        if (requestConfigurer == null) {
            throw new IllegalArgumentException("Null configurer passed to postUrlWithConfigurer.");
        }

        PostMethod post = new PostMethod(url);

        requestConfigurer.configure(post);

        int status = -1;

        try {

            HttpClient client = getConfiguredHttpClient(classInstance);

            status = client.executeMethod(post);

            if (status != 200) {
                LOG.warn("Status wasn't 200, it was " + status);
                return HttpResponse.failure(status, post.getResponseBodyAsStream());
            } else {
                return HttpResponse.success(status, post.getResponseBodyAsStream());
            }

        } catch (IOException e1) {
            LOG.error("Encountered IOException while making request to Veracode.", e1);
        }

        LOG.warn("There was an error and the POST request was not finished.");
        return HttpResponse.failure(status);
    }

    protected HttpClient getConfiguredHttpClient(Class<T> classToProxy) {
        if (httpClientInstance == null) {
            if (proxyService == null) {
                httpClientInstance = new HttpClient();
            } else {
                httpClientInstance = proxyService.getClientWithProxyConfig(classToProxy);
            }
        }

        assert httpClientInstance != null;

        return httpClientInstance;
    }
}
