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

package com.denimgroup.threadfix.webapp.config;

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.NonceService;
import com.denimgroup.threadfix.webapp.filter.CsrfPreventionFilter.LruCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by dzabdi88 on 9/30/14.
 */
public class CustomLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final static Integer SECONDS_IN_MIN = 60;
    private final static Integer MAX_TIMEOUT = 30;
    private final static Integer MIN_TIMEOUT = 1;

    public static final String CSRF_NONCE_SESSION_ATTR_NAME =
            "org.apache.catalina.filters.CSRF_NONCE";

    private int nonceCacheSize = 5;

    @Autowired
    DefaultConfigService defaultConfigService;

    @Autowired
    private NonceService nonceService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();

        Integer sessionTimeout = config.getSessionTimeout();

        if (sessionTimeout != null) {
            sessionTimeout = (sessionTimeout > MAX_TIMEOUT || sessionTimeout < MIN_TIMEOUT) ? MAX_TIMEOUT : sessionTimeout;
            request.getSession().setMaxInactiveInterval(sessionTimeout*SECONDS_IN_MIN);
        }

        DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");

        if(defaultSavedRequest != null){

            String requestUrl = defaultSavedRequest.getRequestURL();

            String nonce = nonceService.generateNonce();

            requestUrl = requestUrl + "?nonce=" + nonce;

            @SuppressWarnings("unchecked")
            LruCache<String> nonceCache =
                    (LruCache<String>) request.getSession(true).getAttribute(
                            CSRF_NONCE_SESSION_ATTR_NAME);

            // generate a new cache if one is not found.
            if (nonceCache == null) {
                nonceCache = new LruCache<>(nonceCacheSize);
                request.getSession().setAttribute(
                        CSRF_NONCE_SESSION_ATTR_NAME, nonceCache);
            }

            nonceCache.add(nonce);

            getRedirectStrategy().sendRedirect(request, response, requestUrl);
        }else{

            super.onAuthenticationSuccess(request, response, authentication);
        }
    }
}
