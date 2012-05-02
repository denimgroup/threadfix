package com.denimgroup.threadfix.webapp.controller;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.service.APIKeyService;

/**
 * This class provides the checkKey method and log implementation to each REST Controller.
 * Having such an abstract class will also allow us to add REST-wide methods later if we need them.
 * @author mcollins
 *
 */
public abstract class RestController {

	protected final Log log = LogFactory.getLog(RestController.class);

	public final static String API_KEY_SUCCESS = "Authentication was successful.";
	public final static String API_KEY_NOT_FOUND_ERROR = "Authentication failed, check your API Key.";
	public final static String RESTRICTED_URL_ERROR = "The requested URL is restricted for your API Key.";

	protected APIKeyService apiKeyService = null;
	
	/**
	 * Implementing classes should add the names of restricted methods to this set
	 * and use the checkRestriction method with the name of the requested method as
	 * a parameter.
	 * <br/><br/>
	 * TODO move to a configuration file? All in code right now.
	 */
	protected static Set<String> restrictedMethods = new HashSet<String>();

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
					+ " did not contain an API Key.");
			return API_KEY_NOT_FOUND_ERROR;
		}

		APIKey key = apiKeyService.loadAPIKey(apiKey);
		boolean validRequest = key != null;

		// TODO take out the actual key here and use the ID?
		// Needs a look after we figure out a more general database encryption strategy
		if (validRequest) {
			log.info("API key " + apiKey + " authenticated successfully on "
					+ request.getPathInfo() + ".");
			
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
