package com.denimgroup.threadfix.importer.impl.remoteprovider.utils;

import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.methods.GetMethod;

import java.io.InputStream;

/**
 * Created by mcollins on 1/5/15.
 */
public class ContrastMockHttpUtils implements RemoteProviderHttpUtils {

    public static final RemoteProviderType type = new RemoteProviderType();

    public static final String GOOD_USERNAME = "user",
            BAD_USERNAME = "bad username",
            GOOD_API_KEY = "api key",
            BAD_API_KEY = "bad api key",
            GOOD_SERVICE_KEY = "service key",
            BAD_SERVICE_KEY = "bad service key",
            BASE_URL_V2 = "https://app.contrastsecurity.com/Contrast/api/",
            BASE_URL_V3 = "https://app.contrastsecurity.com/Contrast/api/ng/",
            GOOD_ENCODING = "dXNlcjpzZXJ2aWNlIGtleQ==", // base64'd GOOD_USERNAME:GOOD_SERVICE_KEY
            ORGS_URL = "/profile/organizations/",
            APPS_URL = "/applications",
            TRACES_URL = "/traces/",
            EVENTS_SUMMARY_URL = "/events/summary";


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
        assert false : "In getUrl(URL, Username, Password) for some reason. This isn't how contrast operates.";
        return HttpResponse.failure();
    }

    @Override
    public HttpResponse getUrlWithConfigurer(String url, RequestConfigurer configurer) {

        GetMethod get = new GetMethod();

        configurer.configure(get);

        testHeader(get, "Authorization", GOOD_ENCODING);
        testHeader(get, "API-Key", GOOD_API_KEY);

        if (url.equals(BASE_URL_V3 + ORGS_URL)) {
            return HttpResponse.success(200, getStream("contrast/orgs.json"));
        } else if (url.startsWith(BASE_URL_V2) && url.endsWith(APPS_URL)) {
            return HttpResponse.success(200, getStream("contrast/apps.json"));
        } else if (!url.startsWith(BASE_URL_V3) && url.startsWith(BASE_URL_V2) && url.contains(TRACES_URL)) {
            String endSection = url.substring(url.indexOf(TRACES_URL) + TRACES_URL.length());
            return HttpResponse.success(200, getStream("contrast/" + endSection + ".json"));
        } else if (url.startsWith(BASE_URL_V3) && url.endsWith(EVENTS_SUMMARY_URL)) {
            return HttpResponse.success(200, getStream("contrast/traces.json"));
        }

        throw new IllegalStateException("A URL other than " + BASE_URL_V2 + " and " + BASE_URL_V3 + " was entered: " + url);
    }

    private void testHeader(GetMethod get, String header1, String value1) {
        Header authHeader = get.getRequestHeader(header1);
        assert authHeader != null : "No value found for Authentication Header. Add to RequestConfigurer.";

        String authentication = authHeader.getValue();
        assert authentication.equals(value1) :
                authentication + " didn't equal " + value1 + ", make sure your Base64 values are working.";
    }

    @Override
    public HttpResponse postUrl(String url, String[] parameters, String[] values) {
        return null;
    }

    @Override
    public HttpResponse postUrl(String url, String[] parameters, String[] values, String username, String password) {
        return HttpResponse.failure();
    }

    @Override
    public HttpResponse postUrl(String url, String[] parameters, String[] values, String username, String password, String[] headerNames, String[] headerVals) {
        return postUrl(url, parameters, values, username, password);
    }

    @Override
    public HttpResponse postUrlWithConfigurer(String url, RequestConfigurer requestConfigurer) {
        return null;
    }
}
