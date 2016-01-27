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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.CheckAPIKeyService;
import com.denimgroup.threadfix.service.ThreadFixUserDetails;
import com.denimgroup.threadfix.util.Result;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;

import static com.denimgroup.threadfix.util.Result.failure;
import static com.denimgroup.threadfix.util.Result.success;

/**
 * This class provides the checkKey method and log implementation to each REST Controller.
 * Having such an abstract class will also allow us to add REST-wide methods later if we need them.
 * @author mcollins
 *
 */
public abstract class TFRestController {

	protected final SanitizedLogger LOG = new SanitizedLogger(this.getClass());

	public final static String API_KEY_SUCCESS = "Authentication was successful.";
	public final static String API_KEY_NOT_FOUND_ERROR = "Authentication failed, check your API Key.";
	public final static String RESTRICTED_URL_ERROR = "The requested URL is restricted for your API Key.";

	@Autowired(required = false)
	protected CheckAPIKeyService checkAPIKeyService;
	@Autowired
	protected APIKeyService apiKeyService;

	/**
	 * This method checks that the key is valid and has permission to use 
	 * the requested method, then returns either API_KEY_SUCCESS,
	 * API_KEY_NOT_FOUND_ERROR, or RESTRICTED_URL_ERROR
	 * @param request
	 * @return
	 */
	protected Result<String> checkKeyGlobal(HttpServletRequest request, RestMethod method) {

		Result<APIKey> lookup = getAPIKey(request);

		if (!lookup.success()) {
			return failure(lookup.getErrorMessage());
		}

		APIKey key = lookup.getResult();
		boolean validRequest = key != null;

		if (validRequest) {
			LOG.debug("API key with ID: " + key.getId() + " authenticated successfully on path: "
					+ request.getPathInfo() + " for methodName: " + method);
			
			if (key.getIsRestrictedKey() && method.restricted) {
					LOG.info("The API key attempted to request a protected URL.");
					return failure(RESTRICTED_URL_ERROR);
			} else {
				return success(API_KEY_SUCCESS);
			}
			
		} else {
			LOG.warn("API key " + request.getParameter("apiKey")
					+ " did not authenticate successfully on "
					+ request.getPathInfo() + ".");
			return failure(API_KEY_NOT_FOUND_ERROR);
		}
	}

	private Result<APIKey> getAPIKey(HttpServletRequest request) {
		String apiKey = request.getParameter("apiKey");

		if (apiKey == null) {
			LOG.warn("Request to " + request.getPathInfo()
					+ " did not contain an API Key(null).");
			return failure(API_KEY_NOT_FOUND_ERROR);
		} else if (apiKey.length() == 0) {
			LOG.warn("Request to " + request.getPathInfo()
					+ " did not contain an API Key(blank).");
			return failure(API_KEY_NOT_FOUND_ERROR);
		}

		APIKey key = apiKeyService.loadAPIKey(apiKey);
		if (key == null) {
			return failure("API Key not found in database.");
		} else {
			return success(key);
		}
	}

	protected Result<String> checkKey(HttpServletRequest request, RestMethod method, int teamId, int appId) {
		if (checkAPIKeyService == null) {
			return checkKeyGlobal(request, method);
		} else {
			return checkAPIKeyService.checkKey(request, method, teamId, appId);
		}
	}

	protected ThreadFixUserDetails getUserDetailsFromApiKeyInRequest(HttpServletRequest request) {
		return checkAPIKeyService == null ? null : checkAPIKeyService.getUserDetailsFromApiKeyInRequest(request);
	}
}
