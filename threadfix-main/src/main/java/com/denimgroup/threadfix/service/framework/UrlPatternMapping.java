package com.denimgroup.threadfix.service.framework;

public class UrlPatternMapping {

	private String servletName, urlPattern;
	
	public UrlPatternMapping(String servletName, String urlPattern) {
		if (servletName == null) {
			throw new IllegalArgumentException("Servlet Name cannot be null.");
		}
		
		if (urlPattern == null) {
			throw new IllegalArgumentException("URL Pattern cannot be null.");
		}
		
		this.servletName = servletName.trim();
		this.urlPattern = urlPattern.trim();
	}
	
	public String getServletName() {
		return servletName;
	}
	
	public String getUrlPattern() {
		return urlPattern;
	}
	
	@Override
	public String toString() {
		return getServletName() + " -> " + getUrlPattern();
	}
}
