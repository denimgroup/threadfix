////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.waf;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;

public class BigIPASMGenerator extends RealTimeProtectionGenerator {

	public BigIPASMGenerator(WafRuleDao wafRuleDao) {
		this.wafRuleDao = wafRuleDao;
	}

	public final static String XML_START = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
											"<signatures export_version=\"11.1.0\">";
	
	public final static String XML_END = "</signatures>";
	
	// BIG IP only accepts certain types of vulnerabilities in its type field. Here they are.
	public String [] acceptedTypes = { "Cross Site Scripting (XSS)", "SQL-Injection", "Command Execution", 
			"Server Side Code Injection", "LDAP Injection", "XPath Injection", "Path Traversal", 
			"Directory Indexing", "Information Leakage", "Predictable Resource Location", "Buffer Overflow", 
			"Denial of Service", "Authentication/Authorization Attacks", "Abuse of Functionality", 
			"Vulnerability Scan", "Detection Evasion", "Other Application Activity", 
			"Other Application Attacks", "Trojan/Backdoor/Spyware", "Non-browser client", 
			"Remote File Include", "HTTP Parser Attack", "HTTP Request Smuggling Attack", "Forceful Browsing", 
			"Brute Force Attack", "Injection Attempt", "Parameter Tampering", "XML Parser Attack", 
			"Session Hijacking", "HTTP Response Splitting", "Web Scraping", "Malicious File Upload", 
			"JSON Parser Attack", "Cross-site Request Forgery"};
	
	public static Map<String, String> CWE_BIG_IP_TYPE_MAP = new HashMap<String, String>();
	static {
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "Cross Site Scripting (XSS)");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_SQL_INJECTION, "SQL-Injection");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_DIRECT_REQUEST, "Forceful Browsing");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_PATH_TRAVERSAL, "Path Traversal");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_XPATH_INJECTION, "XPath Injection");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_DIRECTORY_INDEXING, "Directory Indexing");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_LDAP_INJECTION, "LDAP Injection");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, "Command Execution");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_FORMAT_STRING_INJECTION, "Other Application Attacks");
		CWE_BIG_IP_TYPE_MAP.put(GenericVulnerability.CWE_EVAL_INJECTION, "Server Side Code Injection");
	}
	
	@Override
	public String[] getSupportedVulnerabilityTypes() {
		return new String[] { GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
				GenericVulnerability.CWE_SQL_INJECTION, 
				GenericVulnerability.CWE_DIRECT_REQUEST,
				GenericVulnerability.CWE_PATH_TRAVERSAL,
				GenericVulnerability.CWE_XPATH_INJECTION,
				GenericVulnerability.CWE_DIRECTORY_INDEXING,
				GenericVulnerability.CWE_LDAP_INJECTION,
				GenericVulnerability.CWE_OS_COMMAND_INJECTION,
				GenericVulnerability.CWE_FORMAT_STRING_INJECTION,
				GenericVulnerability.CWE_EVAL_INJECTION };
	}
	
	@Override
	protected String generateRuleWithParameter(String uri, String action, String id,
			String genericVulnName, String parameter) {
		
		String payload = PAYLOAD_MAP.get(genericVulnName);
		String message = MESSAGE_MAP.get(genericVulnName);
		
		String escapedURI = pcreRegexEscape(uri);
		
		String parameterMatching = "(\\?" + parameter + "=|\\?.*&" + parameter + 
				"=|\\n.*[\\n&\\r]" + parameter + "=|\\r.*[\\n&\\r]" + parameter + "=)(" +
				payload + ")";
		
		String pcre = "/" + escapedURI + parameterMatching + "/";
		
		return genBigIPRule(id, pcre, null, message, genericVulnName);
	}
	
	@Override
	protected String generateRuleForExactUrl(String uri, String action,
			String id, String genericVulnName) {
		
		String message = MESSAGE_MAP.get(genericVulnName);
		
		String pcre = "/" + pcreRegexEscape(uri) + "/O";
		
		return genBigIPRule(id, pcre, null, message, genericVulnName);
	}

	@Override
	protected String generateRuleWithPayloadInUrl(String uri, String action,
			String id, String genericVulnName) {
		
		String payload = PAYLOAD_MAP.get(genericVulnName);
		String message = MESSAGE_MAP.get(genericVulnName);
		
		String pcre = "/(" + payload + ")/U";
		
		return genBigIPRule(id, pcre, null, message, genericVulnName);
	}
	
	// TODO add severity in here as the risk field once everything else works
	private String genBigIPRule(String id, String pcre, String date, String doc, String type) {
		
		String bigIPType = CWE_BIG_IP_TYPE_MAP.get(type);
		
		if (!stringInList(bigIPType, acceptedTypes)) {
			return null;
		}
		
		String stringDate = date;
		
		if (stringDate == null) {
			Date tempDate = Calendar.getInstance().getTime();
			DateFormat format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
			stringDate = format.format(tempDate);
		}
		
		// TODO Implement a more general solution
		String filteredRegEx = pcre.replace("\"", "\\x034");
		filteredRegEx = filteredRegEx.replace("'","\\x27");
		filteredRegEx = filteredRegEx.replace("\\r","\\x0D");
		filteredRegEx = filteredRegEx.replace("\\n","\\x0A");
		filteredRegEx = filteredRegEx.replace("&", "\\x26");
		filteredRegEx = filteredRegEx.replace(">", "\\x3E");
		filteredRegEx = filteredRegEx.replace("<", "\\x3C");
		
		return "<sig>" +
				"<rev>" +
				"<sig_name>" + id + "</sig_name>" +
				"<rule>pcre:\"" + filteredRegEx + "\";</rule>" +
				"<last_update>" + stringDate + "</last_update>" +
				"<apply_to>Request</apply_to>" +
				"<risk>3</risk>" +
				"<accuracy>3</accuracy>" +
				"<doc>" + doc + "</doc>" +
				"<attack_type>" + bigIPType + "</attack_type>" +
				"</rev>" +
				"</sig>";
	}
}
