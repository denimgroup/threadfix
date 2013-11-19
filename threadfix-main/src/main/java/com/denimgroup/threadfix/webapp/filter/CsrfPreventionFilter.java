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

import java.io.IOException;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.denimgroup.threadfix.service.SanitizedLogger;

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
	
	//	TODO - Move the creation of SecureRandoms into some sort of shared facility
	//	for the entire application (each class doesn't need to repeat this code)
	private static final String RANDOM_ALGORITHM = "SHA1PRNG";
	private static final String RANDOM_PROVIDER = "SUN";
	
    private SecureRandom randomSource = null;
    
    private final SanitizedLogger log = new SanitizedLogger(CsrfPreventionFilter.class);

    private final Set<String> entryPoints = new HashSet<>();
    private final List<String> entryPointStartPatterns = new ArrayList<>();
    private final List<String> entryPointRegexPatterns = new ArrayList<>();
    private final List<String> protectedRegexPatterns = new ArrayList<>();
    
    private int nonceCacheSize = 5;

    public static final String CSRF_NONCE_SESSION_ATTR_NAME =
        "org.apache.catalina.filters.CSRF_NONCE";
    
    public static final String CSRF_NONCE_REQUEST_PARAM =
        "nonce";

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

            boolean skipNonceCheck = false, skipNonceGeneration = false;
            
            if ("GET".equals(req.getMethod())) {
            	String path = req.getServletPath();
            	if (req.getPathInfo() != null) {
            		path = path + req.getPathInfo();
            	}

            	if (entryPoints.contains(path)) {
            		skipNonceCheck = true;
            	} else {
            		for (String pattern : entryPointStartPatterns) {
            			if (path.startsWith(pattern)) {
            				skipNonceCheck = true;
            				skipNonceGeneration = true;
            				break;
            			}
            		}
            	}
            }
            
            // Check the POST requests too for the regex patterns, then preserve the cache contents.
            if (!skipNonceCheck) {
            	String path = req.getServletPath();
            	if (req.getPathInfo() != null) {
            		path = path + req.getPathInfo();
            	}
    			for (String regex : entryPointRegexPatterns) {
    				if (path.matches(regex)) {
    					skipNonceCheck = true;
    					skipNonceGeneration = true;
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
            
            // if it matches one of the patterns for GET requests, don't check.
            String previousNonce = req.getParameter(CSRF_NONCE_REQUEST_PARAM);
            
            if (!skipNonceCheck && nonceCache != null && !nonceCache.contains(previousNonce)) {
            	
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
        
            // generate a new cache if one is not found.
            if (nonceCache == null) {
                nonceCache = new LruCache<>(nonceCacheSize);
                req.getSession().setAttribute(
                        CSRF_NONCE_SESSION_ATTR_NAME, nonceCache);
            }
            
            // If it matched one of the regexes, don't generate any new nonces.
            // This way links still work with AJAX around.
            if (!skipNonceGeneration) {
            	log.debug("Generating new nonce. Path: " + req.getServletPath());
	            String newNonce = generateNonce();
	            nonceCache.add(newNonce);
	            wResponse = new CsrfResponseWrapper(res, newNonce);
            } else {
            	wResponse = new CsrfResponseWrapper(res, previousNonce);
            }
        }
        
        chain.doFilter(request, wResponse);
    }

    /**
     * Generate a once time token (nonce) for authenticating subsequent
     * requests. This will also add the token to the session. The nonce
     * generation is a simplified version of ManagerBase.generateSessionId().
     * 
     */
    protected String generateNonce() {
        byte random[] = new byte[16];

        // Render the result as a String of hexadecimal digits
        StringBuilder buffer = new StringBuilder();

        if (randomSource == null) {
			try {
				randomSource = SecureRandom.getInstance(RANDOM_ALGORITHM, RANDOM_PROVIDER);
			} catch (NoSuchAlgorithmException e) {
				log.error("Unable to find algorithm " + RANDOM_ALGORITHM, e);
			} catch (NoSuchProviderException e) {
				log.error("Unable to find provider " + RANDOM_PROVIDER, e);
			}
        }
        
        if (randomSource == null) {
        	return null;
        }
        
        randomSource.nextBytes(random);
       
        for (byte element : random) {
            byte b1 = (byte) ((element & 0xf0) >> 4);
            byte b2 = (byte) (element & 0x0f);
            if (b1 < 10) {
                buffer.append((char) ('0' + b1));
            } else {
                buffer.append((char) ('A' + (b1 - 10)));
            }
            
            if (b2 < 10) {
                buffer.append((char) ('0' + b2));
            } else {
                buffer.append((char) ('A' + (b2 - 10)));
            }
        }

        return buffer.toString();
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
         * @param nonce The nonce to add
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
            sb.append(nonce);
            return sb.toString();
        }
    }
    
    private static class LruCache<T> implements Serializable {

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
