package com.denimgroup.threadfix.service;

import javax.servlet.http.HttpServletRequest;

public interface RequestUrlService {

	/**
	 * Returns the string of the base URL queried to the HTTP Servlet
	 * Like: https://hostname:8443/threadfix
	 * Such as the controllers paths appended to this string would make a valid URL
	 * The port number doesn't appear (like in web browsers) if it's standard like 80 or 443
	 */
	public String getBaseUrlFromRequest(HttpServletRequest request);

}
