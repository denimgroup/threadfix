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

package com.denimgroup.threadfix.webapp.filter;

import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class EnterpriseFilter implements Filter {

    enum LicenseState {
        UNKNOWN, NON_ENTERPRISE, VALID, EXPIRED, MISSING_OR_INVALID
    }

    LicenseState state = LicenseState.UNKNOWN;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        determineState();
    }

    private void determineState() {
        assert state == LicenseState.UNKNOWN;

        if (EnterpriseTest.isEnterprise()) {

            if (EnterpriseTest.hasValidLicense()) {
                state = LicenseState.VALID;
            } else if (EnterpriseTest.isLicenseExpired()) {
                state = LicenseState.EXPIRED;
            } else {
                state = LicenseState.MISSING_OR_INVALID;
            }
        } else {
            state = LicenseState.NON_ENTERPRISE;
        }
    }

    @Override
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        assert state != LicenseState.UNKNOWN;

        if (state == LicenseState.VALID || state == LicenseState.NON_ENTERPRISE) {
            chain.doFilter(request, response);
        } else {
            writeError(response);
        }
    }

    private void writeError(ServletResponse response) throws IOException {
        if (response instanceof HttpServletResponse) {

            HttpServletResponse res = (HttpServletResponse) response;

            res.setStatus(403);
            PrintWriter writer = response.getWriter();

            if (state == LicenseState.EXPIRED) {
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
