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

package com.denimgroup.threadfix.service.defects.utils;

import javax.annotation.Nullable;

// Having the interface allows us to mock for testing.
public interface RestUtils {

    public boolean hasXSeraphLoginReason(String urlString, String username, String password);

    @Nullable
    public String getUrlAsString(String urlString, String username, String password);

    @Nullable
    public String postUrlAsString(String urlString, String data, String username, String password, String contentType);

    @Nullable
    public String getPostErrorResponse();

    enum ConnectionStatus {
        VALID, UNAUTHORIZED, OTHER, INVALID, INVALID_CERTIFICATE
    }

    /**
     *
     * @param urlString JIRA URL to connect to
     * @return VALID if we get a HTTP 200,
     *      UNAUTHORIZED if we get an HTTP 401,
     *      OTHER if we get another HTTP response code,
     *      INVALID if a MalformedURLException or IOException is thrown,
     *      INVALID_CERTIFICATE if a SSLHandshakeException is thrown.
     */
    public ConnectionStatus checkConnectionStatus(String urlString);

}
