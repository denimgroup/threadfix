////////////////////////////////////////////////////////////////////////
//
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

package com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure;

import java.util.Map;

/**
 * This is a naive implementation of an HTTP response.
 * We use it to simplify matters in the examples.
 * It is nothing more than a container of the response headers
 * and the response body.
 */
public class Response {

    private Map<String, ? extends Iterable<String>> responseHeaders = null;
    private byte[] responseData = null;
    private int statusCode = 0;

    public Response(
            Map<String, Iterable<String>> responseHeaders,
            byte[] responseData,
            int statusCode) {
        super();
        this.responseHeaders = responseHeaders;
        this.responseData = responseData;
        this.statusCode = statusCode;
    }

    public Response() {}

    /**
     * @return the responseHeaders
     */
    public Map<String, ? extends Iterable<String>> getResponseHeaders() {
        return responseHeaders;
    }

    /**
     * @param responseHeaders
     *            the responseHeaders to set
     */
    public void setResponseHeaders(Map<String, ? extends Iterable<String>> responseHeaders) {
        this.responseHeaders = responseHeaders;
    }

    /**
     * @param responseData
     *            the responseData to set
     */
    public void setResponseData(byte[] responseData) {
        this.responseData = responseData;
    }

    /**
     * @return the statusCode
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * @param statusCode
     *            the statusCode to set
     */
    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    /**
     * @see Object#toString() return the contents of the byte[]
     * data as a string.
     */
    @Override
    public String toString() {

        return new String(this.responseData);
    }

}

