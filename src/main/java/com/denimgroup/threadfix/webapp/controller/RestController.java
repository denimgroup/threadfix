package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.denimgroup.threadfix.service.APIKeyService;

/**
 * This class provides the checkKey method and log implementation to each REST Controller.
 * Having such an abstract class will also allow us to add REST-wide methods later if we need them.
 * @author mcollins
 *
 */
public abstract class RestController {

	protected final Log log = LogFactory.getLog(RestController.class);

	public final static String API_KEY_ERROR = "Authentication failed, check your API Key.";
	
	protected APIKeyService apiKeyService = null;

	protected boolean checkKey(HttpServletRequest request) {
		String apiKey = request.getParameter("apiKey");

		if (apiKey == null) {
			log.warn("Request to " + request.getPathInfo()
					+ " did not contain an API Key.");
			return false;
		}

		boolean authentic = apiKeyService.checkKey(apiKey);

		if (authentic) {
			log.info("API key " + apiKey + " authenticated successfully on "
					+ request.getPathInfo() + ".");
		} else {
			log.warn("API key " + apiKey
					+ " did not authenticate successfully on "
					+ request.getPathInfo() + ".");
		}

		return authentic;
	}
}
