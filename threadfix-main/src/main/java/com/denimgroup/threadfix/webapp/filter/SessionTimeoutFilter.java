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

package com.denimgroup.threadfix.webapp.filter;

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.service.DefaultConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Calendar;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

public class SessionTimeoutFilter extends GenericFilterBean {
    private final static Integer MAX_TIMEOUT = 30;
    private final static Integer MIN_TIMEOUT = 1;

    @Autowired
    SessionRegistry sessionRegistry;
    @Autowired
    DefaultConfigService defaultConfigService;

    private String expiredUrl;
    private LogoutHandler[] handlers = new LogoutHandler[] {new SecurityContextLogoutHandler()};
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    Map<String, Calendar> sessionRefreshTimes = map();

    public SessionTimeoutFilter() {
        expiredUrl = "/login.jsp";
    }

    public SessionTimeoutFilter(String expiredUrl) {
        this.expiredUrl = expiredUrl;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(sessionRegistry, "SessionRegistry required");
        Assert.isTrue(expiredUrl == null || UrlUtils.isValidRedirectUrl(expiredUrl),
                expiredUrl + " isn't a valid redirect URL");
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;

        HttpSession session = request.getSession(false);

        if(session != null) {
            SessionInformation info = sessionRegistry.getSessionInformation(session.getId());
            Calendar lastRefreshTime = sessionRefreshTimes.get(session.getId());
            if (lastRefreshTime == null) {
                lastRefreshTime = Calendar.getInstance();
                sessionRefreshTimes.put(session.getId(), lastRefreshTime);
            }

            if (info != null) {
                if (!info.isExpired()) {
                    Calendar timeoutThreshold = determineTimeoutThreshold();
                    if (timeoutThreshold.getTimeInMillis() > lastRefreshTime.getTimeInMillis()) {
                        info.expireNow();
                        doLogout(request, response);

                        String targetUrl = determineExpiredUrl(request, info);

                        if (targetUrl != null) {
                            redirectStrategy.sendRedirect(request, response, targetUrl);

                            return;
                        } else {
                            response.getWriter().print("This session has been expired due to inactivity.");
                            response.flushBuffer();
                        }

                        return;
                    } else {
                        String requestURI = request.getRequestURI();
                        if (determineIfURIIsRefreshing(requestURI)) {
                            sessionRefreshTimes.put(session.getId(), Calendar.getInstance());
                        }
                    }
                }
            }
        }

        chain.doFilter(request, response);
    }

    protected String determineExpiredUrl(HttpServletRequest request, SessionInformation info) {
        return expiredUrl;
    }

    protected Calendar determineTimeoutThreshold() {
        Calendar timeoutThreshold = Calendar.getInstance();

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();
        Integer sessionTimeout = config.getSessionTimeout();
        if (sessionTimeout != null) {
            sessionTimeout = (sessionTimeout > MAX_TIMEOUT || sessionTimeout < MIN_TIMEOUT) ? MAX_TIMEOUT : sessionTimeout;
        } else {
            sessionTimeout = MAX_TIMEOUT;
        }

        timeoutThreshold.add(Calendar.MINUTE, -1 * sessionTimeout);
        return timeoutThreshold;
    }

    protected boolean determineIfURIIsRefreshing(String uri) {
        // TODO: implement better logic here. We could have a list of regexes to match against
        if (uri.contains("/history/recent/") && uri.contains("/history/objects")) {
            return false;
        }
        return true;
    }

    private void doLogout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        for (LogoutHandler handler : handlers) {
            handler.logout(request, response, auth);
        }
    }

    public void setExpiredUrl(String expiredUrl) {
        Assert.isTrue(expiredUrl == null || UrlUtils.isValidRedirectUrl(expiredUrl),
                expiredUrl + " isn't a valid redirect URL");
        this.expiredUrl = expiredUrl;
    }

    public void setLogoutHandlers(LogoutHandler[] handlers) {
        Assert.notNull(handlers);
        this.handlers = handlers;
    }

    public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }
}
