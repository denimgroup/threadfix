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

import com.denimgroup.threadfix.exception.DefectTrackerCommunicationException;
import com.denimgroup.threadfix.exception.IllegalStateRestException;
import com.denimgroup.threadfix.exception.RestRedirectException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ProxyService;
import com.denimgroup.threadfix.service.defects.HPQualityCenterDefectTracker;
import com.denimgroup.threadfix.service.defects.utils.hpqc.HPQCUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.map;


/**
 * This class keeps the state of the connection for the examples.
 * This class is a  thus sharing state singleton. All examples get
 * the instance in their default constructors - (cookies, server url).
 *
 * Some simple methods are implemented to get commonly used paths.
 *
 */
@Component
public class RestConnector extends SpringBeanAutowiringSupport {

    @Autowired(required = false)
    private ProxyService proxyService;

    private static final SanitizedLogger log = new SanitizedLogger(HPQCUtils.class);

    protected Map<String, String> cookies = map();
    /**
     * This is the URL to the ALM application.
     * For example: http://myhost:8080/qcbin.
     * Make sure that there is no slash at the end.
     */
    protected String              serverUrl;
    protected String              domain;
    protected String              project;

    private int redirectTimes = 0;

    public RestConnector init(
            Map<String, String> cookies,
            String serverUrl,
            String domain,
            String project) {

        this.cookies = cookies;
        this.serverUrl = serverUrl;
        this.domain = domain;
        this.project = project;

        return this;
    }

    public RestConnector reset(
            String serverUrl,
            String domain,
            String project) {

        this.serverUrl = serverUrl;
        this.domain = domain;
        this.project = project;

        return this;
    }

    public String buildEntityCollectionUrl(String entityType) {
        return buildUrl("rest/domains/"
                + domain
                + "/projects/"
                + project
                + "/"
                + entityType
                + "s");
    }

    public String buildEntityUrl(String entityType, String entityId) {
        return buildUrl("rest/domains/"
                + domain
                + "/projects/"
                + project
                + "/"
                + entityType
                + "s"
                + "/"
                + entityId);
    }

    /**
     * @param path
     *            on the server to use
     * @return a url on the server for the path parameter
     */
    @Nonnull
    public String buildUrl(String path) {

        return String.format("%1$s/%2$s", serverUrl, path);
    }

    @Nonnull
    public Response httpPost(String url, byte[] data, Map<String,
            String> headers) {

        return doHttp("POST", url, null, data, headers);
    }

    @Nonnull
    public Response httpGet(String url, String queryString, Map<String,
            String> headers) {

        return doHttp("GET", url, queryString, null, headers);
    }

    /**
     * @param type
     *            http operation: get post put delete
     * @param url
     *            to work on
     * @param queryString
     * @param data
     *            to write, if a writable operation
     * @param headers
     *            to use in the request
     * @return http response
     */
    @Nonnull
    private Response doHttp(
            String type,
            String url,
            String queryString,
            byte[] data,
            Map<String, String> headers) {
        HttpURLConnection con;
        try {

            if ((queryString != null) && !queryString.isEmpty()) {
                url += "?" + queryString;
            }

            if (proxyService != null) {
                con = proxyService.getConnectionWithProxyConfig(new URL(url), HPQualityCenterDefectTracker.class);
            } else {
                con = (HttpURLConnection) new URL(url).openConnection();
            }

            assert con != null;

            con.setRequestMethod(type);
            String cookieString = getCookieString();

            prepareHttpRequest(con, headers, data, cookieString);
            con.connect();
            Response ret = retrieveHtmlResponse(con);

            updateCookies(ret);

            // Reset redirect counting
            redirectTimes = 0;
            return ret;

        } catch (IOException e) {
            redirectTimes = 0;
            throw new DefectTrackerCommunicationException(e, "Unable to communicate with the HPQC server.");
        } catch (RestRedirectException e) {

            // Only redirect up to 5 times
            if (redirectTimes >= 5) {
                log.warn("Already redirected " + redirectTimes +" times, not going to do it anymore");
                redirectTimes = 0;
                throw e;
            }

            redirectTimes ++;
            log.info("Redirecting " + redirectTimes +" times to " + e.getTargetUrl());
            return doHttp(type, e.getTargetUrl(), queryString, data, headers);
        }

    }

    /**
     * @param con
     *            connection to set the headers and bytes in
     * @param headers
     *            to use in the request, such as content-type
     * @param bytes
     *            the actual data to post in the connection.
     * @param cookieString
     *            the cookies data from clientside, such as lwsso,
    qcsession, jsession etc.
     * @throws java.io.IOException
     */
    private void prepareHttpRequest(
            HttpURLConnection con,
            Map<String, String> headers,
            byte[] bytes,
            String cookieString) throws IOException {

        String contentType = null;

        //attach cookie information if such exists
        if ((cookieString != null) && !cookieString.isEmpty()) {

            con.setRequestProperty("Cookie", cookieString);
        }

        //send data from headers
        if (headers != null) {

            //Skip the content-type header - should only be sent
            //if you actually have any content to send. see below.
            contentType = headers.remove("Content-Type");

            for (Entry<String, String> header : headers.entrySet()) {
                con.setRequestProperty(header.getKey(), header.getValue());
            }
        }

        // If there's data to attach to the request, it's handled here.
        // Note that if data exists, we take into account previously removed
        // content-type.
        if ((bytes != null) && (bytes.length > 0)) {

            con.setDoOutput(true);

            //warning: if you add content-type header then you MUST send
            // information or receive error.
            //so only do so if you're writing information...
            if (contentType != null) {
                con.setRequestProperty("Content-Type", contentType);
            }

            OutputStream out = con.getOutputStream();
            out.write(bytes);
            out.flush();
            out.close();
        }
    }

    /**
     * @param con
     *            that is already connected to its url with an http request,
     *            and that should contain a response for us to retrieve
     * @return a response from the server to the previously submitted
     *            http request
     * @throws IOException
     */
    @Nonnull
    private Response retrieveHtmlResponse(HttpURLConnection con) throws IOException {

        if (con == null) {
            throw new IllegalStateRestException("Invalid connection, unable to continue.");
        }

        int responseCode = con.getResponseCode();
        if (responseCode == 302) {
            String redirectTarget = con.getHeaderField("Location");
            log.error("Got redirected to " + redirectTarget);
            throw new RestRedirectException("Redirected to " + redirectTarget, redirectTarget);
        }

        Response ret = new Response();

        ret.setStatusCode(responseCode);
        ret.setResponseHeaders(con.getHeaderFields());

        InputStream inputStream;
        //select the source of the input bytes, first try 'regular' input
        try {
            if (responseCode == 401) // Un-authorized
                inputStream = con.getErrorStream();
            else
                inputStream = con.getInputStream();
        } catch (IOException e) {
            log.error("Received IOException trying to get the InputStream from the connection object." +
                    " Attempting to get the error text.");

            inputStream = con.getErrorStream();
        }

        if (inputStream == null) {
            throw new DefectTrackerCommunicationException(
                    "Server response was null, received response code " + responseCode);
        }

        // This actually takes the data from the previously set stream
        // (error or input) and stores it in a byte[] inside the response
        ByteArrayOutputStream container = new ByteArrayOutputStream();

        byte[] buf = new byte[1024];
        int read;
        while ((read = inputStream.read(buf, 0, 1024)) > 0) {
            container.write(buf, 0, read);
        }

        ret.setResponseData(container.toByteArray());

        log.debug("Response from HPQC was " + ret);

        return ret;
    }

    public void updateCookies(Response response) {

        Iterable<String> newCookies =
                response.getResponseHeaders().get("Set-Cookie");
        if (newCookies != null) {

            for (String cookie : newCookies) {
                int equalIndex = cookie.indexOf('=');
                int semicolonIndex = cookie.indexOf(';');

                String cookieKey = cookie.substring(0, equalIndex);
                String cookieValue =
                        cookie.substring(equalIndex + 1, semicolonIndex);

                cookies.put(cookieKey, cookieValue);
            }
        }
    }

    @Nonnull
    public String getCookieString() {

        StringBuilder sb = new StringBuilder();

        if (!cookies.isEmpty()) {

            Set<Entry<String, String>> cookieEntries = cookies.entrySet();
            for (Entry<String, String> entry : cookieEntries) {
                sb.append(entry.getKey()).append("=").append(entry.getValue()).append(";");
            }
        }

        return sb.toString();
    }
}