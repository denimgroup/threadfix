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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.APIKeyService;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * This class provides the checkKey method and log implementation to each REST Controller.
 * Having such an abstract class will also allow us to add REST-wide methods later if we need them.
 * @author mcollins
 *
 */
public abstract class TFRestController {

	protected final SanitizedLogger log = new SanitizedLogger(this.getClass());

	public final static String API_KEY_SUCCESS = "Authentication was successful.";
	public final static String API_KEY_NOT_FOUND_ERROR = "Authentication failed, check your API Key.";
	public final static String RESTRICTED_URL_ERROR = "The requested URL is restricted for your API Key.";

	@Autowired
	protected APIKeyService apiKeyService;

	/**
	 * Implementing classes should add the names of restricted methods to this set
	 * and use the checkRestriction method with the name of the requested method as
	 * a parameter.
	 * <br/><br/>
	 * TODO move to a configuration file. All in code right now.
	 */
	protected static Set<String> restrictedMethods = set();

	/**
	 * This method checks that the key is valid and has permission to use 
	 * the requested method, then returns either API_KEY_SUCCESS,
	 * API_KEY_NOT_FOUND_ERROR, or RESTRICTED_URL_ERROR
	 * @param request
	 * @return
	 */
	protected String checkKey(HttpServletRequest request, String methodName) {		
		String apiKey = request.getParameter("apiKey");

		if (apiKey == null) {
			log.warn("Request to " + request.getPathInfo()
					+ " did not contain an API Key(null).");
			return API_KEY_NOT_FOUND_ERROR;
		} else if(apiKey.length() == 0) {
            log.warn("Request to " + request.getPathInfo()
                    + " did not contain an API Key(blank).");
            return API_KEY_NOT_FOUND_ERROR;
        }

		APIKey key = apiKeyService.loadAPIKey(apiKey);
		boolean validRequest = key != null;

		if (validRequest) {
			log.info("API key with ID: " + key.getId() + " authenticated successfully on path: "
					+ request.getPathInfo() + " for methodName: " + methodName);
			
			if (key.getIsRestrictedKey() &&
				restrictedMethods.contains(methodName)) {
					log.info("The API key attempted to request a protected URL.");
					return RESTRICTED_URL_ERROR;
			} else {
				return API_KEY_SUCCESS;
			}
			
		} else {
			log.warn("API key " + apiKey
					+ " did not authenticate successfully on "
					+ request.getPathInfo() + ".");
			return API_KEY_NOT_FOUND_ERROR;
		}
	}
}
