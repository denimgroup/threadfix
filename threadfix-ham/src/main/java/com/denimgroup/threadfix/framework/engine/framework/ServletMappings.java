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
package com.denimgroup.threadfix.framework.engine.framework;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.impl.spring.SpringServletConfigurationChecker;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class ServletMappings {

	private static final SanitizedLogger log = new SanitizedLogger("ServletMappings");

	public final static String DEFAULT_SERVLET = "Default Servlet";
	
	@Nonnull
    private final List<UrlPatternMapping>
		allServletMappings,
		pathMappings = list(),
		extensionMappings = list(),
		exactMappings = list();
		
	@Nonnull
    private final List<ClassMapping> servlets;
	
	@Nonnull
    private final ProjectDirectory projectDirectory;

    @Nonnull
    private final Map<String, String> contextParams;
	
	@Nonnull
    private UrlPatternMapping defaultServlet = new UrlPatternMapping(DEFAULT_SERVLET,"/");

    @Nonnull
    private UrlPatternMapping contextRootServlet = defaultServlet;
	
	///////////////////////////////////////////////////////////////////////////
	//                     Initialization methods                            //
	///////////////////////////////////////////////////////////////////////////
	
	public ServletMappings(@Nonnull List<UrlPatternMapping> servletMappings,
                           @Nonnull List<ClassMapping> servlets,
                           @Nonnull ProjectDirectory projectDirectory,
                           @Nonnull Map<String, String> contextParams) {
		this.allServletMappings = servletMappings;
		this.servlets = servlets;
		this.projectDirectory = projectDirectory;
        this.contextParams = contextParams;
		
		sortMappings();
	}
	
	private void sortMappings() {
		if (allServletMappings.isEmpty()) {
			return;
		}
		
		for (UrlPatternMapping mapping : allServletMappings) {
			if (mapping == null) {
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
	
	@Nullable
    public List<UrlPatternMapping> getServletMappings() {
		return allServletMappings;
	}
	
	@Nullable
    public List<ClassMapping> getClassMappings() {
		return servlets;
	}
	
	///////////////////////////////////////////////////////////////////////////
	//                         Public methods                                //
	///////////////////////////////////////////////////////////////////////////
	
	/**
	 * Returns a list of URL patterns
	 * @return List containing url patterns, or empty list if none are found.
	 */
	@Nonnull
    public List<String> getURLPatternsForClass(@Nonnull String classWithPackage) {
		List<String> mappings = list();

		String servletName = null;
		
		for (ClassMapping entry : servlets) {
			if (entry != null && classWithPackage.equals(entry.getClassWithPackage())) {
				servletName = entry.getServletName();
				break;
			}
		}
		
		for (UrlPatternMapping entry : allServletMappings) {
			if (entry != null && entry.getServletName().equals(servletName)) {
				mappings.add(entry.getUrlPattern());
			}
		}
		
		return mappings;
	}
	
	/**
	 * Get a class based on a URL
	 * @return default servlet, or a class if one is found.
	 */
	@Nonnull
    public String getClassForURL(@Nonnull String path) {
		String servletName = findServletName(path);
		
		for (ClassMapping entry : servlets) {
			if (entry != null && servletName.equals(entry.getServletName())) {
				return entry.getClassWithPackage();
			}
		}
		
		return DEFAULT_SERVLET;
	}
	
	@Nonnull
    public FrameworkType guessApplicationType() {
		// Since we're only looking at two types of applications, this logic is pretty simple
		// In a full-blown implementation, this method would be able to return lots of other types too.
		FrameworkType frameworkType = FrameworkType.JSP;
		
        log.info("About to guess application type from web.xml.");

        for (ClassMapping mapping : servlets) {
            if (SpringServletConfigurationChecker.checkServletConfig(projectDirectory, mapping, contextParams)) {
                frameworkType = FrameworkType.SPRING_MVC;
            }
        }

		log.info("Determined that the framework type was " + frameworkType);
		return frameworkType;
	}
	
	///////////////////////////////////////////////////////////////////////////
	//                         Utility methods                               //
	///////////////////////////////////////////////////////////////////////////
	

	// TODO make sure the path coming in does not have the application context root included

    /**
     * @return the servlet name, or null if none is found
     */
    @Nonnull
	private String findServletName(@Nonnull String path) {
		
		if (path.equals("") || path.equals("/")) {
			// Use context root servlet
            return contextRootServlet.getServletName();
		}
		
		// Step text is from http://jcp.org/aboutJava/communityprocess/final/jsr315/
		
		// Step 1.
		// The container will try to find an exact match of the path of the request to
		// the path of the servlet. A successful match selects the servlet.
		
		if (exactMappings.size() > 1) {
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
		if (pathMappings.size() > 1) {
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
		if (!extensionMappings.isEmpty()) {
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
        return defaultServlet.getServletName();
	}
	
	private int getMatchLength(@Nonnull String path, @Nonnull String urlPattern) {
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
	
	@Nonnull
    private String stringAfterSegment(@Nonnull String string, @Nonnull String segment) {
		return string.substring(string.indexOf(segment) + segment.length());
	}
	
	@Nullable
    private String getNextPathSegment(@Nullable String input) {
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
