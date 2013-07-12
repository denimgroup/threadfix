package com.denimgroup.threadfix.service.framework;

import java.util.ArrayList;
import java.util.List;

import com.denimgroup.threadfix.service.merge.FrameworkType;

public class ServletMappings {
	
	public final static String DEFAULT_SERVLET = "Default Servlet";
	
	private List<UrlPatternMapping> 
		allServletMappings = null,
		pathMappings = new ArrayList<>(),
		extensionMappings = new ArrayList<>(),
		exactMappings = new ArrayList<>();
		
	private List<ClassMapping> servlets = null;
	
	private UrlPatternMapping
		defaultServlet = null,
		contextRootServlet = null;
	
	///////////////////////////////////////////////////////////////////////////
	//                     Initialization methods                            //
	///////////////////////////////////////////////////////////////////////////
	
	public ServletMappings(List<UrlPatternMapping> servletMappings,
			List<ClassMapping> servlets) {
		this.allServletMappings = servletMappings;
		this.servlets = servlets;
		
		sortMappings();
	}
	
	private void sortMappings() {
		if (allServletMappings == null || allServletMappings.isEmpty()) {
			return;
		}
		
		for (UrlPatternMapping mapping : allServletMappings) {
			if (mapping == null || mapping.getUrlPattern() == null) {
				continue;
			}
			
			String urlMapping = mapping.getUrlPattern();
			
			if (urlMapping.equals("/")) {
				defaultServlet = mapping;
				
			} else if (urlMapping.equals("")) {
				contextRootServlet = mapping;
				
			} else if (urlMapping.startsWith("/") &&
					mapping.getUrlPattern().endsWith("/*")) {
				pathMappings.add(mapping);
				
			} else if (urlMapping.startsWith("*.")) {
				extensionMappings.add(mapping);
				
			} else {
				exactMappings.add(mapping);
			}
		}
	}
	
	public List<UrlPatternMapping> getServletMappings() {
		return allServletMappings;
	}
	
	public List<ClassMapping> getClassMappings() {
		return servlets;
	}
	
	///////////////////////////////////////////////////////////////////////////
	//                         Public methods                                //
	///////////////////////////////////////////////////////////////////////////
	
	/**
	 * Returns a list of URL patterns
	 * @param classWithPackage
	 * @return List containing url patterns, or empty list if none are found.
	 */
	public List<String> getURLPatternsForClass(String classWithPackage) {
		List<String> mappings = new ArrayList<>();
		
		if (classWithPackage == null || servlets == null || allServletMappings == null) {
			return mappings;
		}
		
		String servletName = null;
		
		for (ClassMapping entry : servlets) {
			if (entry != null && classWithPackage.equals(entry.getClassWithPackage())) {
				servletName = entry.getServletName();
				break;
			}
		}
		
		for (UrlPatternMapping entry : allServletMappings) {
			if (entry != null && entry.getUrlPattern() != null &&
					entry.getServletName().equals(servletName)) {
				mappings.add(entry.getUrlPattern());
			}
		}
		
		return mappings;
	}
	
	/**
	 * Get a class based on a URL
	 * @param url
	 * @return default servlet, or a class if one is found.
	 */
	public String getClassForURL(String path) {
		if (path == null || servlets == null || allServletMappings == null) {
			return DEFAULT_SERVLET;
		}
		
		String servletName = findServletName(path);
		
		if (servletName == null) {
			// this should never happen, we should at least get the default mapping
			return DEFAULT_SERVLET;
		}
		
		for (ClassMapping entry : servlets) {
			if (entry != null && servletName.equals(entry.getServletName())) {
				return entry.getClassWithPackage();
			}
		}
		
		return DEFAULT_SERVLET;
	}
	
	public FrameworkType guessApplicationType() {
		
		for (ClassMapping mapping : servlets) {
			if (mapping.getClassWithPackage().equals(
						"org.springframework.web.servlet.DispatcherServlet")) {
				
				// If it's using  a Spring DispatcherServlet, we need to check for
				// Spring config, not normal config
				// TODO see about creating a hybrid spring / normal servlet
				return FrameworkType.SPRING_MVC;
			}
		}

		// Since we're only looking at two types of applications, this logic is pretty simple
		// In a full-blown implementation, this method would be able to return lots of other types too.
		return FrameworkType.JSP;
	}
	
	///////////////////////////////////////////////////////////////////////////
	//                         Utility methods                               //
	///////////////////////////////////////////////////////////////////////////
	

	// TODO make sure the path coming in does not have the application context root included
	private String findServletName(String path) {
		
		if (path.equals("") || path.equals("/")) {
			// Use context root servlet
			if (contextRootServlet != null) {
				return contextRootServlet.getServletName();
			}
		}
		
		// Step text is from http://jcp.org/aboutJava/communityprocess/final/jsr315/
		
		// Step 1. 
		// The container will try to find an exact match of the path of the request to 
		// the path of the servlet. A successful match selects the servlet.
		
		if (exactMappings != null && exactMappings.size() > 1) {
			for (UrlPatternMapping exactMapping : exactMappings) {
				if (path.equals(exactMapping.getUrlPattern())) {
					return exactMapping.getServletName();
				}
			}
		}
		
		// Step 2.
		// The container will recursively try to match the longest path-prefix. This is done
		// by stepping down the path tree a directory at a time, using the / character as a
		// path separator. The longest match determines the servlet selected.
		if (pathMappings != null && pathMappings.size() > 1) {
			UrlPatternMapping currentLongest = null;
			int longest = 0;
			for (UrlPatternMapping pathEntry : pathMappings) {
				int length = getMatchLength(path, pathEntry.getUrlPattern());
				if (length > longest) {
					currentLongest = pathEntry;
					longest = length;
				}
			}
			
			if (currentLongest != null) {
				return currentLongest.getServletName();
			}
		}
		
		// Step 3.
		// If the last segment in the URL path contains an extension (e.g. .jsp), 
		// the servlet container will try to match a servlet that handles requests 
		// for the extension. An extension is defined as the part of the last segment 
		// after the last . character.
		if (extensionMappings != null && !extensionMappings.isEmpty()) {
			for (UrlPatternMapping extensionEntry : extensionMappings) {
				if (extensionEntry.getUrlPattern().length() <= 2) {
					continue;
				}
				
				String extension = extensionEntry.getUrlPattern().substring(1);
				
				if (path.endsWith(extension)) {
					return extensionEntry.getServletName();
				}
			}
		}
		
		// Step 4.
		// If none of the previous three rules result in a servlet match, the container 
		// will attempt to serve content appropriate for the resource requested. If a 
		// "default" servlet is defined for the application, it will be used. Many containers 
		// provide an implicit default servlet for serving content.
		if (defaultServlet != null) {
			return defaultServlet.getServletName();
		} else {
			return DEFAULT_SERVLET;
		}
	}
	
	private int getMatchLength(String path, String urlPattern) {
		String pathPart = getNextPathSegment(path),
				urlPart = getNextPathSegment(urlPattern);
		
		if (pathPart != null && urlPart != null && pathPart.equals(urlPart)) {
			return 1 + getMatchLength(stringAfterSegment(path, pathPart), stringAfterSegment(urlPattern, urlPart));
		} else if (urlPattern.replaceAll("/\\*$","/").equals(path + "/")) {
			return 1;
		} else {
			return 0;
		}
	}
	
	private String stringAfterSegment(String string, String segment) {
		return string.substring(string.indexOf(segment) + segment.length());
	}
	
	private String getNextPathSegment(String input) {
		if (input != null && 
				input.startsWith("/") && 
				input.length() > 1) {
			
			String pathPart = input.substring(1);
			
			if (pathPart.contains("/")) {
				pathPart = pathPart.substring(0, pathPart.indexOf('/'));
				return pathPart;
			}
		}
		
		return null;
	}
	
}
