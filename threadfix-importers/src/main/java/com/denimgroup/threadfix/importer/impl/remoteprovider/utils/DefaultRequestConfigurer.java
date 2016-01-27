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
package com.denimgroup.threadfix.importer.impl.remoteprovider.utils;

import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Created by mcollins on 1/22/15.
 */
public class DefaultRequestConfigurer implements RequestConfigurer {

    public String username, password;

    public String[] headerNames, headerVals, parameterNames, parameterVals;

    public String contentType = "text/xml; charset=UTF-8";

    public String requestBody = null, requestBodyContentType = null;

    public DefaultRequestConfigurer withUsernamePassword(String username, String password) {
        this.username = username;
        this.password = password;
        return this;
    }

    public DefaultRequestConfigurer withHeaders(String[] headerNames, String[] headerVals) {
        if (headerNames == null) {
            throw new IllegalArgumentException("Null value passed to withHeaders for parameter headerNames");
        }

        if (headerVals == null) {
            throw new IllegalArgumentException("Null value passed to withHeaders for parameter headerVals");
        }

        if (headerNames.length != headerVals.length) {
            throw new IllegalArgumentException("Header names and values were of different lengths. " +
                    "names.length = " + headerNames.length + ", values.length = " + headerVals.length);
        }

        this.headerNames = headerNames;
        this.headerVals = headerVals;

        return this;
    }

    public DefaultRequestConfigurer withPostParameters(String[] parameterNames, String[] parameterVals) {
        if (parameterNames == null) {
            throw new IllegalArgumentException("Null value passed to withParameters for parameter parameterNames");
        }

        if (parameterVals == null) {
            throw new IllegalArgumentException("Null value passed to withParameters for parameter parameterVals");
        }

        if (parameterNames.length != parameterVals.length) {
            throw new IllegalArgumentException("parameter names and values were of different lengths. " +
                    "names.length = " + parameterNames.length + ", values.length = " + parameterVals.length);
        }

        this.parameterNames = parameterNames;
        this.parameterVals = parameterVals;

        return this;
    }

    public DefaultRequestConfigurer withContentType(String contentType) {
        if (contentType == null) {
            throw new IllegalArgumentException("Null contentType passed to withContentType");
        }

        this.contentType = contentType;
        return this;
    }

    @Override
    public void configure(HttpMethodBase method) {
        if (username != null && password != null) {
            String login = username + ":" + password;
            String encodedLogin = DatatypeConverter.printBase64Binary(login.getBytes());

            method.setRequestHeader("Authorization", "Basic " + encodedLogin);
        }

        method.setRequestHeader("Content-type", contentType);

        if (headerNames != null && headerVals != null && headerNames.length == headerVals.length) {
            for (int i = 0; i < headerNames.length; i++) {
                method.setRequestHeader(headerNames[i], headerVals[i]);
            }
        }

        if (method instanceof PostMethod) {
            PostMethod postVersion = (PostMethod) method;
            if (parameterNames != null && parameterVals != null && parameterNames.length == parameterVals.length) {
                for (int i = 0; i < parameterNames.length; i++) {
                    postVersion.setParameter(parameterNames[i], parameterVals[i]);
                }
            }

            if (requestBody != null) {
                postVersion.setRequestEntity(getRequestEntity());
            }
        } // if it's a get then the parameters should be in the URL
    }

    private RequestEntity getRequestEntity() {
        return new RequestEntity() {
            @Override
            public boolean isRepeatable() {
                return false;
            }

            @Override
            public void writeRequest(OutputStream out) throws IOException {
                out.write(requestBody.getBytes());
            }

            @Override
            public long getContentLength() {
                return requestBody.length();
            }

            @Override
            public String getContentType() {
                return requestBodyContentType;
            }
        };
    }

    public DefaultRequestConfigurer withRequestBody(String body, String type) {
        this.requestBody = body;
        this.requestBodyContentType = type;
        return this;
    }
}