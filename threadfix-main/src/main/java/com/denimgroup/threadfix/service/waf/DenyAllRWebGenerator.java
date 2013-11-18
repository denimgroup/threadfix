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

import java.util.HashMap;
import java.util.Map;

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;

/**
 * @author mcollins
 * 
 */
public class DenyAllRWebGenerator extends RealTimeProtectionGenerator {

	// templateStart + pattern + templateMiddle + id + templateEnd + action = rule
	// the {id} is the denyall filter id, not the threadfix wafrule id.
	
	String templateStart  = "security_blacklist add-filter {id} --pattern \"";
	String templateMiddle = "\" --type URI -d ";
	String templateEnd    = " --action ";
	
	public DenyAllRWebGenerator(WafRuleDao wafRuleDao, WafRuleDirectiveDao wafRuleDirectiveDao) {
		this.wafRuleDao = wafRuleDao;
		this.wafRuleDirectiveDao = wafRuleDirectiveDao;
		this.defaultDirective = "deny";
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
	
	// TODO Test all of these POSIX payloads
	// Canonicalization knocks down the number of characters we need to filter
	
	// things need to be double-escaped
	public static final String POSIX_SQL_INJECTION = "['\\\\\\\\\\\\\"-]";
	public static final String POSIX_XSS = "[<>]";
	public static final String POSIX_PATH_TRAVERSAL = "[\\.\\\\]";
	public static final String POSIX_HTTP_RESPONSE_SPLITTING = "%5cn|%5cr|%0d|%0a";
	public static final String POSIX_XPATH_INJECTION = "['\\\\\\\\\\\\\"]";
	public static final String POSIX_DIRECTORY_INDEXING = "[ \\.$?]";
	public static final String POSIX_LDAP_INJECTION = "[\\()*]";
	public static final String POSIX_OS_COMMAND_INJECTION = "[&|;]";
	public static final String POSIX_FORMAT_STRING_INJECTION = "[%]";
	public static final String POSIX_EVAL_INJECTION = "[;]";

	protected static final Map<String, String> POSIX_PAYLOAD_MAP = new HashMap<>();
	static {
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, POSIX_XSS);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_SQL_INJECTION, POSIX_SQL_INJECTION);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_PATH_TRAVERSAL, POSIX_PATH_TRAVERSAL);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, POSIX_HTTP_RESPONSE_SPLITTING);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_XPATH_INJECTION, POSIX_XPATH_INJECTION);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_DIRECTORY_INDEXING, POSIX_DIRECTORY_INDEXING);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_LDAP_INJECTION, POSIX_LDAP_INJECTION);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, POSIX_OS_COMMAND_INJECTION);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_FORMAT_STRING_INJECTION, POSIX_FORMAT_STRING_INJECTION);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_DIRECT_REQUEST, POSIX_DIRECTORY_INDEXING);
		POSIX_PAYLOAD_MAP.put(GenericVulnerability.CWE_EVAL_INJECTION, POSIX_EVAL_INJECTION);
	}
	
	@Override
	protected String generateRuleWithParameter(String uri, String action, String id,
			String genericVulnName, String parameter) {
		
		String payload = POSIX_PAYLOAD_MAP.get(genericVulnName);
		payload = payload.replace(";", "\\;");
		payload = payload.replace("\"", "\\\"");
		String pattern = uri + ".*" + parameter + "=.*" + payload;

		return templateStart + pattern + templateMiddle + id + templateEnd + action;
	}
	
	@Override
	protected String generateRuleForExactUrl(String uri, String action,
			String id, String genericVulnName) {
		
		String payload = POSIX_PAYLOAD_MAP.get(genericVulnName);
		payload = payload.replace(";", "\\;");
		payload = payload.replace("\"", "\\\"");
		String pattern = uri + payload;

		return templateStart + pattern + templateMiddle + id + templateEnd + action;
	}

	@Override
	protected String generateRuleWithPayloadInUrl(String uri, String action,
			String id, String genericVulnName) {
		
		String payload = POSIX_PAYLOAD_MAP.get(genericVulnName);
		payload = payload.replace(";", "\\;");
		payload = payload.replace("\"", "\\\"");
		String pattern = uri + ".*" + payload + "";
		
		return templateStart + pattern + templateMiddle + id + templateEnd + action;
	}
}
