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
    private Exception failure = null;
    private int statusCode = 0;

    public Response(
            Map<String, Iterable<String>> responseHeaders,
            byte[] responseData,
            Exception failure,
            int statusCode) {
        super();
        this.responseHeaders = responseHeaders;
        this.responseData = responseData;
        this.failure = failure;
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
     * @return the responseData
     */
    public byte[] getResponseData() {
        return responseData;
    }

    /**
     * @param responseData
     *            the responseData to set
     */
    public void setResponseData(byte[] responseData) {
        this.responseData = responseData;
    }

    /**
     * @return the failure if the access to the requested URL failed,
     * such as a 404 or 500.
     *  If no such failure occured this method returns null.
     */
    public Exception getFailure() {
        return failure;
    }

    /**
     * @param failure
     *            the failure to set
     */
    public void setFailure(Exception failure) {
        this.failure = failure;
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

