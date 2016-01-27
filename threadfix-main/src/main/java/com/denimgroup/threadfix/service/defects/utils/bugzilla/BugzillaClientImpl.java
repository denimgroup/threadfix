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
package com.denimgroup.threadfix.service.defects.utils.bugzilla;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ProxyService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.BugzillaDefectTracker;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientConfigImpl;
import org.apache.xmlrpc.client.XmlRpcCommonsTransportFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class BugzillaClientImpl extends SpringBeanAutowiringSupport implements BugzillaClient {

    @Autowired(required = false)
    private ProxyService proxyService;

    protected final static SanitizedLogger LOG = new SanitizedLogger(BugzillaClientImpl.class);

    private BugzillaClientImpl(){}

    public static BugzillaClient getInstance() {
        return new BugzillaClientImpl();
    }

    private XmlRpcClient client = null;

    ConnectionStatus lastStatus = ConnectionStatus.INVALID;

    String url, username, password;

    @Override
    @SuppressWarnings("unchecked") // it's hard to get around this because of type erasure
    public Map<String, Integer> createBug(Map<String, String> bugMap) throws XmlRpcException {
        if (client == null) {
            client = initializeClient();
        }

        if (client == null) {
            return null;
        }

        Object returnMap = executeMethod("Bug.create", bugMap);

        // this only gives a little type safety
        return returnMap instanceof Map<?, ?> ? (HashMap<String, Integer>) returnMap : null;
    }

    @Override
    public ConnectionStatus configure(String url, String username, String password) throws XmlRpcException{

        assert url != null;

        if (lastStatus == ConnectionStatus.VALID && url.equals(this.url) &&
                username != null && password != null &&
                username.equals(this.username) && password.equals(this.password)) {
            return lastStatus;
        }

        ConnectionStatus returnStatus = ConnectionStatus.INVALID;

        this.url = url;
        this.username = username == null ? "" : username;
        this.password = password == null ? "" : password;

        XmlRpcClient client = initializeClient();
        if (client != null) {
            String loginStatus = null;
            try {
                loginStatus = login(client);
            } catch (XmlRpcException e) {
                LOG.error("Encountered XmlRpcException while trying to log in.", e);
                throw e;
            }

            // TODO Pass this information back to the user
            if (loginStatus != null) {
                if (loginStatus.equals(AbstractDefectTracker.LOGIN_FAILURE)
                        || loginStatus.equals(AbstractDefectTracker.BAD_CONFIGURATION)) {
                    LOG.warn("Login Failed, check credentials");
                    return ConnectionStatus.INVALID;
                } else {
                    returnStatus = ConnectionStatus.VALID;
                }
            }
        }

        lastStatus = returnStatus;

        return returnStatus;
    }

    @Override
    public Object executeMethod(String method) throws XmlRpcException {
        return executeMethod(method, new Object[]{});
    }

    @Override
    public Object executeMethod(String method, Object... params) throws XmlRpcException {
        if (method == null || params == null)
            return null;

        assert method.equals("User.login") || lastStatus == ConnectionStatus.VALID : "The connection should be configured before being used.";

        if (client == null) {
            client = initializeClient();
            String loginResponse = login(client);
            if (loginResponse == null) {
                return null;
            }
            if (loginResponse.equals(AbstractDefectTracker.LOGIN_FAILURE) ||
                    loginResponse.equals(AbstractDefectTracker.BAD_CONFIGURATION)) {
                LOG.warn("Login Failed, check credentials");
                return null;
            }
        }

        if (client == null) {
            LOG.warn("There was an error initializing the Bugzilla client.");
            return null;
        }

        return client.execute(method, params);
    }

    /**
     * @param client
     * @throws XmlRpcException
     */
    private String login(XmlRpcClient client) throws XmlRpcException {

        Map<String, String> loginMap = new HashMap<>();
        loginMap.put("login", this.username == null ? "" : this.username);
        loginMap.put("password", this.password == null ? "" : this.password);
        loginMap.put("rememberlogin", "Bugzilla_remember");

        Object[] loginArray = new Object[1];
        loginArray[0] = loginMap;

        Object loginResult;
        try {
            loginResult = client.execute("User.login", loginArray);
        } catch (IllegalArgumentException e2) {
            if (e2.getMessage().contains("Host name may not be null")) {
                return AbstractDefectTracker.BAD_CONFIGURATION;
            } else {
                LOG.error("Encountered IllegalArgumentException", e2);
                return AbstractDefectTracker.BAD_CONFIGURATION;
            }
        }

        if (loginResult == null) {
            return null;
        } else {
            return loginResult.toString();
        }
    }

    /**
     * Set up the configuration
     */
    private XmlRpcClient initializeClient() {

        assert this.url != null : "This would cause a NullPointerException below.";

        // Get the RPC client set up and ready to go
        // The alternate TransportFactory stuff is required so that cookies
        // work and the logins behave persistently
        XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
        try {
            config.setServerURL(new URL(this.url));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        // config.setEnabledForExtensions(true);
        XmlRpcClient client = new XmlRpcClient();
        client.setConfig(config);
        XmlRpcCommonsTransportFactory factory = new XmlRpcCommonsTransportFactory(client);

        HttpClient httpClient = proxyService == null ? new HttpClient() : proxyService.getClientWithProxyConfig(BugzillaDefectTracker.class);
        factory.setHttpClient(httpClient);

        client.setTransportFactory(factory);

        return client;
    }

    @Override
    public boolean checkUrl(String url) {

        assert url != null : "Null URLs cause null pointer exceptions.";

        this.url = url;

        XmlRpcClient client = initializeClient();
        if (client == null) {
            LOG.error("Received null client from initializeClient(). Either the code or the URL is invalid");
            return false;
        }

        Map<String, String> loginMap = new HashMap<>();
        loginMap.put("login", " ");
        loginMap.put("password", " ");
        loginMap.put("rememberlogin", "Bugzilla_remember");

        try {
            executeMethod("User.login", loginMap);
            LOG.error("Shouldn't be here, we just logged into " +
                    "Bugzilla with blank username / password.");
            assert false;
            return false; // TODO figure out the correct fallback here
        } catch (XmlRpcException e) {
            if (e.getMessage().contains("The username or password you entered is not valid")) {
                LOG.info("The URL was good, received an authentication warning.");
                return true;
            } else if (e.getMessage().contains(
                    "I/O error while communicating with HTTP server")) {
                LOG.warn("Unable to retrieve a RPC response from that URL. Returning false.");
                return false;
            } else {
                LOG.warn("Something went wrong. Check out the error. Returning false.", e);
                return false;
            }
        } catch (IllegalArgumentException e2) {
            LOG.warn("IllegalArgumentException was tripped. Returning false.");
            return false;
        }
    }

}
