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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.util.Result;
import com.denimgroup.threadfix.webapp.controller.rest.RestMethod;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by mcollins on 7/27/15.
 */
public interface CheckAPIKeyService {
    public final static String API_KEY_SUCCESS = "Authentication was successful.";
    public final static String API_KEY_NOT_FOUND_ERROR = "Authentication failed, check your API Key.";
    public final static String RESTRICTED_URL_ERROR = "The requested URL is restricted for your API Key.";

    Result<String> checkKey(HttpServletRequest request, RestMethod method, int teamId, int appId);

    ThreadFixUserDetails getUserDetailsFromApiKeyInRequest(HttpServletRequest request);
}
