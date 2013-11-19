////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.waf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringEscapeUtils;

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.service.SanitizedLogger;

/**
 * 
 * This class facilitates adding support for new WAF types. To use, just subclass this class,
 * write these three methods:
 * 	generateRuleWithParameter       - for a known location and parameter (lots of stuff)
 * 	generateRuleForExactUrl         - for a known URL (directory traversal, forced browsing)
 * 	generateRuleWithPayloadInUrl    - for cases where the payload isn't in a parameter
 * 
 * and also the method getSupportedVulnerabilityTypes, so that you can control which vuln types
 * get rules generated for them. 
 * 
 * You will also need to add some directives to the database and add the WAF type to
 * RealTimeProtectionGeneratorFactory.
 * 
 * @author bbeverly
 * @author mcollins
 * 	
 */
public abstract class RealTimeProtectionGenerator {
	
	protected WafRuleDao wafRuleDao;
	protected WafRuleDirectiveDao wafRuleDirectiveDao;
	protected final SanitizedLogger log = new SanitizedLogger(this.getClass());
	
	protected String defaultDirective = "deny";

	// Should find ' " -- and URL-encoded equivalents (27, 22, 2D2D)
	public static final String PAYLOAD_SQL_INJECTION = "'|\\%27|\\\"|\\%22|--|\\%2D\\%2D";
	public static final String PAYLOAD_XSS = "<|\\%3C|>|\\%3E";
	// TODO May want to support .2E and 2E.
	// TODO Need to test this more.
	public static final String PAYLOAD_PATH_TRAVERSAL = "\\.\\\\|\\./|\\%2E\\\\|\\%2E/";
	// TODO Need to verify the encoding here
	public static final String PAYLOAD_HTTP_RESPONSE_SPLITTING = "%5cn|%5cr|%0d|%0a";
	public static final String PAYLOAD_XPATH_INJECTION = "'|\\%27|\\\"|\\%22";
	public static final String PAYLOAD_DIRECTORY_INDEXING = " |%20|\\n|$|\\?|\\/\\?|\\/\\n|\\/$|\\/ |\\/%20";
	public static final String PAYLOAD_LDAP_INJECTION = "\\\\|\\(|\\)|\\*|\\%5c|\\%2a|\\%28|\\%29";
	public static final String PAYLOAD_OS_COMMAND_INJECTION = "&|\\||;|%7C|%26|%3B";
	public static final String PAYLOAD_FORMAT_STRING_INJECTION = "\\%|\\%25";
	public static final String PAYLOAD_EVAL_INJECTION = ";|\\%3b";
	
	// These maps allow you to easily add new types of vulnerabilities if they :
	// 1. Follow one of the patterns
	// 2. Have a known payload
	protected static final Map<String, String> PAYLOAD_MAP = new HashMap<>();
	static {
		PAYLOAD_MAP.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, PAYLOAD_XSS);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_SQL_INJECTION, PAYLOAD_SQL_INJECTION);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_PATH_TRAVERSAL, PAYLOAD_PATH_TRAVERSAL);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, PAYLOAD_HTTP_RESPONSE_SPLITTING);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_XPATH_INJECTION, PAYLOAD_XPATH_INJECTION);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_DIRECTORY_INDEXING, PAYLOAD_DIRECTORY_INDEXING);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_LDAP_INJECTION, PAYLOAD_LDAP_INJECTION);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, PAYLOAD_OS_COMMAND_INJECTION);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_FORMAT_STRING_INJECTION, PAYLOAD_FORMAT_STRING_INJECTION);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_DIRECT_REQUEST, PAYLOAD_DIRECTORY_INDEXING);
		PAYLOAD_MAP.put(GenericVulnerability.CWE_EVAL_INJECTION, PAYLOAD_EVAL_INJECTION);
	}
	
	protected static final Map<String, String> MESSAGE_MAP = new HashMap<>();
	static {
		MESSAGE_MAP.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "Cross-site Scripting attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_SQL_INJECTION, "SQL Injection attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_PATH_TRAVERSAL, "Path Traversal attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, "HTTP Response Splitting attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_XPATH_INJECTION, "XPath Injection attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_DIRECTORY_INDEXING, "Directory Indexing attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_LDAP_INJECTION, "LDAP Injection attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, "OS Command Injection attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_FORMAT_STRING_INJECTION, "Format String Injection attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_DIRECT_REQUEST, "Direct Request attempt");
		MESSAGE_MAP.put(GenericVulnerability.CWE_EVAL_INJECTION, "Eval Injection attempt");
	}
	
	/**
	 * 
	 * @return A String array of generic vulnerability types that should have parameters.
	 */
	protected String[] getVulnerabilitiesWithParameters() {
		return new String[] { GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
				GenericVulnerability.CWE_SQL_INJECTION, 
				GenericVulnerability.CWE_PATH_TRAVERSAL,
				GenericVulnerability.CWE_XPATH_INJECTION,
				GenericVulnerability.CWE_LDAP_INJECTION,
				GenericVulnerability.CWE_OS_COMMAND_INJECTION,
				GenericVulnerability.CWE_FORMAT_STRING_INJECTION,
				GenericVulnerability.CWE_EVAL_INJECTION };
	}
	
	/**
	 * 
	 * @return A String array of generic vulnerability types that have their payload in the URL.
	 */
	protected String[] getVulnerabilitiesWithPayloadInUrl() {
		return new String[] { GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
				GenericVulnerability.CWE_SQL_INJECTION };
	}

	/**
	 * 
	 * @return A String array of generic vulnerability types that need protection at an exact URL.
	 */
	protected String[] getVulnerabilitiesAtExactUrl() {
		return new String[] { GenericVulnerability.CWE_DIRECTORY_INDEXING,
				GenericVulnerability.CWE_DIRECT_REQUEST };
	}
	
	/**
	 * This method is used to determine whether a rule can be generated for a given vulnerability.
	 * @return
	 */
	protected abstract String[] getSupportedVulnerabilityTypes();
	
	/**
	 * This method should be overwritten by classes that use the default makeRule implementation.
	 * @param uri
	 * @param action
	 * @param id
	 * @param payload
	 * @param parameter
	 * @param message
	 * @return A rule filtering the URL for a given parameter payload.
	 */
	protected String generateRuleWithParameter(String uri, String action, String id,
			String genericVulnName, String parameter) { 
		log.warn("The RealTimeProtectionGenerator implementation of generateRuleWithParameter() has been called."
				+ " This indicates that the class extending RealTimeProtectionGenerator is incomplete.");
		return null; 
	}
	
	/**
	 * This method should be overwritten by classes that use the default makeRule implementation.
	 * @param uri
	 * @param action
	 * @param id
	 * @param payload
	 * @param message
	 * @return A rule prohibiting access to the exact URI.
	 */
	protected String generateRuleForExactUrl(String uri, String action, String id,
			String genericVulnName) { 
		log.warn("The RealTimeProtectionGenerator implementation of generateRuleForExactUrl() has been called."
				+ " This indicates that the class extending RealTimeProtectionGenerator is incomplete.");
		return null; 
	}
	
	/**
	 * This method should be overwritten by classes that use the default makeRule implementation.
	 * @param uri
	 * @param action
	 * @param id
	 * @param payload
	 * @param message
	 * @return A rule filtering the URL for a given payload.
	 */
	protected String generateRuleWithPayloadInUrl(String uri, String action, String id,
			String genericVulnName) { 
		log.warn("The RealTimeProtectionGenerator implementation of generateRuleWithPayloadInUrl() has been called."
				+ " This indicates that the class extending RealTimeProtectionGenerator is incomplete.");
		return null; 
	}

	/**
	 * 
	 * @param waf
	 * @param directive
	 * @return
	 */
	public List<WafRule> generateRules(Waf waf, WafRuleDirective directive) {
		if (waf == null || waf.getApplications() == null || waf.getApplications().size() == 0)
			return new ArrayList<>();
	
		List<Application> applications = waf.getApplications();
		
		if (applications == null) {
			log.warn("No Applications found, no rules could be generated.");
			return new ArrayList<>();
		}

		log.info("About to generate rules for the WAF " + StringEscapeUtils.escapeHtml(waf.getName()) + 
				": " + applications.size() + " applications.");

		int numVulns = 0;
		for (Application application : applications) {
			if (application != null && application.isActive())
				numVulns += application.getVulnerabilities().size();
		}
		log.info("This will involve " + numVulns + " vulnerabilities.");

		List<WafRule> allRules = new ArrayList<>();

		for (Application app : applications) {
			if (app == null || !app.isActive())
				continue;
			
			List<WafRule> newRules = generateRules(app, directive);
			if (newRules != null && newRules.size() != 0) {
				for (WafRule newRule : newRules) {
					if (newRule != null && newRule.getRule() != null) {
						allRules.add(newRule);
					}
				}
			}
		}

		return allRules;
	}

	/**
	 * 
	 * @param application
	 * @param directive
	 * @return
	 */
	protected List<WafRule> generateRules(Application application, WafRuleDirective directive) {
		if (application == null || application.getVulnerabilities() == null
				|| application.getVulnerabilities().size() == 0 || application.getWaf() == null
				|| application.getWaf().getWafType() == null) {
			return null;
		}

		log.info("Generating rules for "
				+ application.getVulnerabilities().size() + " vulnerabilities");

		List<WafRule> rules = new ArrayList<>();

		for (Vulnerability vuln : application.getVulnerabilities()) {
			if (vuln == null || vuln.getIsFalsePositive())
				continue;
			
			WafRule oldRule = null;
			if (wafRuleDao != null && directive != null)
				oldRule = wafRuleDao.retrieveByVulnerabilityAndWafAndDirective(vuln, application.getWaf(), directive);
			WafRule currentRule = null;
			if (oldRule == null) {
				currentRule = makeRule(application.getWaf().getCurrentId(), vuln, directive);
				if (currentRule != null) {
					currentRule.setVulnerability(vuln);
					application.getWaf().setCurrentId(application.getWaf().getCurrentId() + 1);
				}
			} else {
				currentRule = oldRule;
			}

			if (currentRule != null && currentRule.getRule() != null
					&& !currentRule.getRule().trim().equals("")) {
				rules.add(currentRule);
			} else {
				log.debug("New rule was null or empty for vulnerability: " + vuln);
			}
		}

		return rules;
	}
	
	/**
	 * 
	 * @param genericVulnName
	 * @param uri
	 * @param action
	 * @param id
	 * @param parameter
	 * @return
	 */
	protected String generateRuleText(String genericVulnName, String uri, String action, 
			String id, String parameter, Vulnerability vuln) {
		String rule = null;
		
		if (parameter != null && !parameter.isEmpty()) {
			if (stringInList(genericVulnName, getVulnerabilitiesWithParameters())) {
				rule = generateRuleWithParameter(uri, action, id, 
					genericVulnName, parameter);
			}
		}
	
		if (rule == null && stringInList(genericVulnName, getVulnerabilitiesWithPayloadInUrl())) { 
			rule = generateRuleWithPayloadInUrl(uri, action, id, 
					genericVulnName);
		}
		
		if (rule == null && stringInList(genericVulnName, getVulnerabilitiesAtExactUrl())) { 
			rule = generateRuleForExactUrl(uri, action, id, 
					genericVulnName);
		}
		
		if (rule != null) {
			String vulnName = MESSAGE_MAP.get(genericVulnName);
			if (vulnName != null) {
				vulnName = vulnName.replaceFirst(" attempt", "");
				log.debug("New " + StringEscapeUtils.escapeHtml(vulnName) + " rule was " + StringEscapeUtils.escapeHtml(rule.trim()));
			}
		}
			
		return rule;
	}

	/**
	 * 
	 * @param currentId
	 * @param vulnerability
	 * @param directive
	 * @return
	 */
	protected WafRule makeRule(Integer currentId, Vulnerability vulnerability, WafRuleDirective directive) {
		if (currentId == null || vulnerability == null 
				|| vulnerability.getSurfaceLocation() == null
				|| vulnerability.getGenericVulnerability() == null
				|| vulnerability.getGenericVulnerability().getName() == null) {
			return null;
		}
	
		String action = defaultDirective;
		if (directive != null && directive.getDirective() != null)
			action = directive.getDirective();
		
		SurfaceLocation surfaceLocation = vulnerability.getSurfaceLocation();
	
		String vulnType = vulnerability.getGenericVulnerability().getName();
		// Check if the vuln is supported
		if (!stringInList(vulnType, getSupportedVulnerabilityTypes()))
			return null;
		
		String vulnUrl = surfaceLocation.getPath();
		
		// TODO remove this, it should be unnecessary.
		String param = null;
		if (surfaceLocation.getParameter() != null && !surfaceLocation.getParameter().isEmpty())
			param = surfaceLocation.getParameter().replaceFirst("param=", "");
	
		String rule = generateRuleText(vulnType, vulnUrl, action, currentId.toString(), param, vulnerability);
	
		if (rule != null) {
			WafRule newRule = new WafRule();
			newRule.setRule(rule);
			newRule.setNativeId(currentId.toString());
			return newRule;
		}
		return null;
	}

	/**
	 * TODO this list of characters is probably fine, but needs to be double checked
	 * @param toEscape
	 * @return
	 */
	protected String pcreRegexEscape(String toEscape) {
		String [] characters = { "[", "]", "\\", "^", "$", ".", "?", "*", "+", "|", "(", ")", "/" };
		
		String returnString = toEscape;
		
		for (String character : characters)
			if (returnString.contains(character))
				returnString = returnString.replace(character, "\\" + character);
		
		return returnString;
	}

	/**
	 * TODO avoid this method by using a set for the acceptable Strings?
	 * @param string
	 * @param list
	 * @return
	 */
	protected boolean stringInList(String string, String[] list) {
		for (int i = 0; i < list.length; i++)
			if (string.equals(list[i]))
				return true;
			
		return false;
	}
	
	public static boolean hasStartAndEnd(String type) {
		return type.equals(WafType.BIG_IP_ASM) || 
			   type.equals(WafType.IMPERVA_SECURE_SPHERE);
	}
	
	public static String getStart(String type, List<WafRule> rules) {
		if (type.equals(WafType.BIG_IP_ASM)) {
			return BigIPASMGenerator.getStart(rules);
		} else if (type.equals(WafType.IMPERVA_SECURE_SPHERE)) {
			return ImpervaSecureSphereGenerator.getStart(rules);
		} else {
			return null;
		}
	}
	
	public static String getEnd(String type, List<WafRule> rules) {
		if (type.equals(WafType.BIG_IP_ASM)) {
			return BigIPASMGenerator.getEnd(rules);
		} else if (type.equals(WafType.IMPERVA_SECURE_SPHERE)) {
			return ImpervaSecureSphereGenerator.getEnd(rules);
		} else {
			return null;
		}
	}
		
	public WafRuleDirective getDefaultDirective(Waf waf) {
		if (waf != null && waf.getWafType() != null) {
			return wafRuleDirectiveDao.retrieveByWafTypeIdAndDirective(
						waf.getWafType(), defaultDirective);
		} else {
			return null;
		}
	}
	
}
