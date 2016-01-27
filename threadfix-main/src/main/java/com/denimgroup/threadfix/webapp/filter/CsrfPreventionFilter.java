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

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * 
 * This file has been edited from its original version by Denim Group, Ltd.
 * 
 */

package com.denimgroup.threadfix.webapp.filter;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.NonceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Provides basic CSRF protection for a web application. The filter assumes
 * that:
 * <ul>
 * <li>The filter is mapped to /*</li>
 * <li>{@link HttpServletResponse#encodeRedirectURL(String)} and
 * {@link HttpServletResponse#encodeURL(String)} are used to encode all URLs
 * returned to the client
 * </ul>
 */
public class CsrfPreventionFilter extends SpringBeanAutowiringSupport implements Filter {

    private final SanitizedLogger log = new SanitizedLogger(CsrfPreventionFilter.class);

    private final Set<String> entryPoints = new HashSet<>();
    private final List<String> entryPointStartPatterns = list();
    private final List<String> entryPointRegexPatterns = list();
    private final List<String> protectedRegexPatterns = list();

    private int nonceCacheSize = 5;

    public static final String CSRF_NONCE_SESSION_ATTR_NAME =
        "org.apache.catalina.filters.CSRF_NONCE";
    
    public static final String CSRF_NONCE_REQUEST_PARAM =
        "nonce";

    public Set<String> noRedirectPaths = set(
            "/rest/", "/scripts/", "/images/", "/styles/", "/history/recent/", "/login.jsp");

    @Autowired
    private NonceService nonceService;

    /**
     * Entry points are URLs that will not be tested for the presence of a valid
     * nonce. They are used to provide a way to navigate back to a protected
     * application after navigating away from it. Entry points will be limited
     * to HTTP GET requests and should not trigger any security sensitive
     * actions.
     * 
     * @param entryPoints   Comma separated list of URLs to be configured as
     *                      entry points.
     */
    public void setEntryPoints(String entryPoints) {
        String values[] = entryPoints.split(",");
        for (String value : values) {
        	if (value == null) {
        		continue;
        	}

            if (value.trim().contains("\n")) {
                String error = "Newlines are not allowed in patterns. line: " + value;
                log.error(error);
                throw new IllegalStateException(error);
            } else if (value.trim().startsWith("regex ")) {
        		this.entryPointRegexPatterns.add(value.trim().substring(6));
        	} else if (value.trim().startsWith("protected-regex ")) {
        		this.protectedRegexPatterns.add(value.trim().substring(16));
        	} else if (value.contains("*")) {
        		this.entryPointStartPatterns.add(value.substring(0,value.indexOf('*')).trim());
        	} else {
        		this.entryPoints.add(value.trim());
        	}
        }
    }

    /**
     * Sets the number of previously issued nonces that will be cached on a LRU
     * basis to support parallel requests, limited use of the refresh and back
     * in the browser and similar behaviors that may result in the submission
     * of a previous nonce rather than the current one. If not set, the default
     * value of 5 will be used.
     * 
     * @param nonceCacheSize    The number of nonces to cache
     */
    public void setNonceCacheSize(int nonceCacheSize) {
        this.nonceCacheSize = nonceCacheSize;
    }
    
    @Override
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        ServletResponse wResponse = response;

        if (request instanceof HttpServletRequest &&
                response instanceof HttpServletResponse) {
            
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse res = (HttpServletResponse) response;

            boolean skipNonceCheck = false, skipNonceGeneration = false, canRedirect = true;

            String path = req.getServletPath();
            if ("GET".equals(req.getMethod())) {
            	if (req.getPathInfo() != null) {
            		path = path + req.getPathInfo();
            	}

            	if (entryPoints.contains(path)) {
            		skipNonceCheck = true;
            	} else {
            		for (String pattern : entryPointStartPatterns) {
            			if (path.startsWith(pattern)) {
                            if (noRedirectPaths.contains(pattern)) {
                                canRedirect = false;
                            }

            				skipNonceCheck = true;
            				skipNonceGeneration = true;
            				break;
            			}
            		}
            	}
            }
            
            // Check the POST requests too for the regex patterns, then preserve the cache contents.
            if (!skipNonceCheck) {
            	if (req.getPathInfo() != null) {
            		path = path + req.getPathInfo();
            	}
    			for (String regex : entryPointRegexPatterns) {
    				if (path.matches(regex)) {
    					skipNonceCheck = true;
    					skipNonceGeneration = true;

                        for (String noRedirectPath : noRedirectPaths) {
                            if (regex.contains(noRedirectPath)) {
                                canRedirect = false;
                            }
                        }
                        break;
    				}
    			}
    			
    			if (!skipNonceGeneration) {
    				for (String regex : protectedRegexPatterns) {
    					if (path.matches(regex)) {
    						skipNonceGeneration = true;
                            break;
    					}
    				}
    			}
    		}
        
            @SuppressWarnings("unchecked")
            LruCache<String> nonceCache =
                (LruCache<String>) req.getSession(true).getAttribute(
                    CSRF_NONCE_SESSION_ATTR_NAME);

            // generate a new cache if one is not found.
            if (nonceCache == null) {
                nonceCache = new LruCache<>(nonceCacheSize);
                req.getSession().setAttribute(
                        CSRF_NONCE_SESSION_ATTR_NAME, nonceCache);
            }
            
            // if it matches one of the patterns for GET requests, don't check.

            String previousNonce = req.getParameter(CSRF_NONCE_REQUEST_PARAM);

            boolean hasValidNonce = nonceCache.contains(previousNonce);

            if (!skipNonceCheck && !hasValidNonce) {
            	
            	String nonceStatus = previousNonce == null ? "Missing nonce" : "Incorrect nonce";
            	
            	SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");
            	
            	log.warn("CSRF Filter blocked a request:" +
          			  " reason: " + nonceStatus +
          			 ", address: " + request.getRemoteAddr() +
          			 ", path: " + req.getServletPath() +
          			 ", time: " + dateFormatter.format(Calendar.getInstance().getTime()));

            	res.sendError(HttpServletResponse.SC_NO_CONTENT);
            	return;
            }

            // if the request doesn't need CSRF protection and doesn't have a valid token,
            // let's give them one. This avoids all sorts of issues with non-sensitive pages expiring
            boolean redirect = canRedirect && !hasValidNonce && skipNonceCheck;
            if (redirect) {
                String newNonce = nonceService.generateNonce();
                nonceCache.add(newNonce);

                String newPath = req.getContextPath() + path + "?nonce=" + newNonce;
                log.info("Redirecting " + path);

                res.sendRedirect(newPath);
            } else if (!skipNonceGeneration) {

                // If it matched one of the regexes, don't generate any new nonces.
                // This way links still work with AJAX around.
                log.debug("Generating new nonce. Path: " + req.getServletPath());
                String newNonce = nonceService.generateNonce();
                nonceCache.add(newNonce);

                wResponse = new CsrfResponseWrapper(res, newNonce);
            } else {
            	wResponse = new CsrfResponseWrapper(res, previousNonce);
            }

            req.getSession().removeAttribute("redirectFromLogin");
        }
        
        chain.doFilter(request, wResponse);
    }

    private static class CsrfResponseWrapper
            extends HttpServletResponseWrapper {

        private String nonce;

        public CsrfResponseWrapper(HttpServletResponse response, String nonce) {
            super(response);
            this.nonce = nonce;
        }

        @Override
        @Deprecated
        public String encodeRedirectUrl(String url) {
            return encodeRedirectURL(url);
        }

        @Override
        public String encodeRedirectURL(String url) {
            return addNonce(super.encodeRedirectURL(url));
        }

        @Override
        @Deprecated
        public String encodeUrl(String url) {
            return encodeURL(url);
        }

        @Override
        public String encodeURL(String url) {
            return addNonce(super.encodeURL(url));
        }
        
        /**
         * Return the specified URL with the nonce added to the query string
         *
         * @param url URL to be modified
         */
        private String addNonce(String url) {
            if (url == null || nonce == null) {
				return url;
			}

            String path = url;
            
            if (path.contains("?")) {
            	path = path.substring(0,path.indexOf('?'));
            }
            
            StringBuilder sb = new StringBuilder(path);
            sb.append('?');
            sb.append(CSRF_NONCE_REQUEST_PARAM);
            sb.append('=');
            try {
                sb.append(URLEncoder.encode(nonce, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                // we should make threadfix die at this point
                throw new RuntimeException("UTF-8 was not supported.", e);
            }
            return sb.toString();
        }
    }
    
    public static class LruCache<T> implements Serializable {

    	private static final long serialVersionUID = 2034805024625345966L;
    	
		// Although the internal implementation uses a Map, this cache
        // implementation is only concerned with the keys.
        private final Map<T,T> cache;
        
        public LruCache(final int cacheSize) {
            cache = new LinkedHashMap<T,T>() {
                private static final long serialVersionUID = 1L;
                @Override
                protected boolean removeEldestEntry(Map.Entry<T,T> eldest) {
                    if (size() > cacheSize) {
                        return true;
                    }
                    return false;
                }
            };
        }
        
        public void add(T key) {
            cache.put(key, null);
        }
        
        public boolean contains(T key) {
            return cache.containsKey(key);
        }
    }

    @Override
	public void init(FilterConfig filterConfig) throws ServletException {
		Enumeration<String> paramNames = filterConfig.getInitParameterNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            if ("entryPoints".equals(paramName)) {
            	setEntryPoints(filterConfig.getInitParameter("entryPoints"));
            } else if ("nonceCacheSize".equals(paramName)) {
            	String temp = filterConfig.getInitParameter("nonceCacheSize");
            	if (temp != null && Integer.valueOf(temp) != null) {
					setNonceCacheSize(Integer.valueOf(temp));
				}
            }
        }
    }

	@Override
	public void destroy() {
	}
}
