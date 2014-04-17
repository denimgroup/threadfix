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

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * 
 * This file has been edited from its original version by Denim Group, Ltd.
 * 
 */

package com.denimgroup.threadfix.webapp.filter;

import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Provides basic CSRF protection for a web application. The filter assumes
 * that:
 * <ul>
 * <li>The filter is mapped to /*</li>
 * <li>{@link javax.servlet.http.HttpServletResponse#encodeRedirectURL(String)} and
 * {@link javax.servlet.http.HttpServletResponse#encodeURL(String)} are used to encode all URLs
 * returned to the client
 * </ul>
 */
public class EnterpriseFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        if (EnterpriseTest.isEnterprise()) {

            if (EnterpriseTest.hasValidLicense()) {
                chain.doFilter(request, response);
            } else {
                writeError(response);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    private void writeError(ServletResponse response) throws IOException {
        if (response instanceof HttpServletResponse) {

            HttpServletResponse res = (HttpServletResponse) response;

            res.setStatus(403);
            PrintWriter writer = response.getWriter();

            if (EnterpriseTest.isLicenseExpired()) {
                writer.write("<h1 style=\"text-align:center\">ThreadFix license has expired. Install a valid license and try again.</h1>");
            } else {
                writer.write("<h1 style=\"text-align:center\">ThreadFix license check failed. Install a valid license and try again.</h1>");
            }
            writer.close();
        }
    }

    @Override
    public void destroy() {

    }

}
