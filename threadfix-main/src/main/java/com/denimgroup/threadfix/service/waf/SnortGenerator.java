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
 * @author bbeverly
 * @author mcollins
 * 
 */
public class SnortGenerator extends RealTimeProtectionGenerator {

	// Intended use:
	// STR_FIND_PARAM_START + param_name + STR_FIND_PARAM_MID + target_payload +
	// STR_FIND_END
	public static final String STR_FIND_PARAM_START = "/[?&]";
	public static final String STR_FIND_PARAM_MID = "=[^?&]*";
	public static final String STR_FIND_PARAM_END = "/Ui\"";
	
	public static final String PAYLOAD_SQL_INJECTION = "(\\x27|\\x22|\\x2D\\x2D)";
	public static final String PAYLOAD_XSS = "[\\x3C\\x3E\\x22\\x27\\x3B]";
	public static final String PAYLOAD_PATH_TRAVERSAL = "(\\x2E\\x2F|\\x2E\\x5C)";
	public static final String PAYLOAD_HTTP_RESPONSE_SPLITTING = "[\\x0D\\0A]";
	public static final String PAYLOAD_XPATH_INJECTION = "[\\x27\\x22]";
	public static final String PAYLOAD_DIRECTORY_INDEXING = "[\\x20\\x0D\\x24\\x3F\\x2F]";
	public static final String PAYLOAD_LDAP_INJECTION = "[\\x5c\\x2a\\x28\\x29]";
	public static final String PAYLOAD_OS_COMMAND_INJECTION = "[&\\x7C\\x3B]";
	public static final String PAYLOAD_FORMAT_STRING_INJECTION = "\\x25";
	public static final String PAYLOAD_EVAL_INJECTION = "[\\x3B\\x7C\\x26\\x3E\\x60]";

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
	
	public SnortGenerator(WafRuleDao wafRuleDao, WafRuleDirectiveDao wafRuleDirectiveDao) {
		this.wafRuleDao = wafRuleDao;
		this.wafRuleDirectiveDao = wafRuleDirectiveDao;
		this.defaultDirective = "drop";
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
		
		payload = payload.replace(";", "\\;");
		
		return action + " tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (" +
						"msg:\"" + message + "\"; " +
						"flow: to_server,established; " +
						"content:\"" + uri + "?\"; http_uri; " +
						"content:\"" + parameter + "=\"; http_uri; " +
						"pcre:\""
			+ STR_FIND_PARAM_START + parameter + STR_FIND_PARAM_MID + payload
			+ STR_FIND_PARAM_END
			+ "; metadata:service http; "
			+ "classtype:web-application-attack; sid:" + id + ";)";
	}
	
	@Override
	protected String generateRuleForExactUrl(String uri, String action,
			String id, String genericVulnName) {
		
		String payload = PAYLOAD_MAP.get(genericVulnName);
		String message = MESSAGE_MAP.get(genericVulnName);
		
		payload = payload.replace(";", "\\;");
		
		return action + " tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (" +
						"msg:\"" + message + "\"; " +
						"flow: to_server,established; " +
						"content:\"" + uri + "\"; http_uri;" +
						"metadata:service http; " +
						"classtype:web-application-attack; sid:" + id + ";)";
	}

	@Override
	protected String generateRuleWithPayloadInUrl(String uri, String action,
			String id, String genericVulnName) {
		String payload = PAYLOAD_MAP.get(genericVulnName);
		String message = MESSAGE_MAP.get(genericVulnName);
		
		payload = payload.replace(";", "\\;");
		
		return action + " tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (" +
						"msg:\"" + message + "\"; " +
						"flow: to_server,established; " +
						"content:\"" + uri + "\"; http_uri;" +
						"pcre:\"/" + payload + "/Ui\"; " +
						"metadata:service http; " +
						"classtype:web-application-attack; sid:" + id + ";)";
	}
}
