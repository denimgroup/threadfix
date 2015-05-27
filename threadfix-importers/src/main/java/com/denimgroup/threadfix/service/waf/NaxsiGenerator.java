////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2015 NBS System
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
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.waf;

import com.denimgroup.threadfix.annotations.WebApplicationFirewall;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.WafType;


import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * @author jvoisin
 */

@WebApplicationFirewall(name = WafType.NAXSI)
public class NaxsiGenerator extends RealTimeProtectionGenerator {
	/* Payloads to blacklist */
	protected static final String NX_XPATH_INJECTION = "rx:\\(|\\)|'|\\\"";
	protected static final String NX_PATH_TRAVERSAL = "str:..";
	protected static final String NX_LDAP_INJECTION = "rx:&|\\|=|~|<|>|\\*|\\(|\\)";
	protected static final String NX_SQL_INJECTION = "rx:\\\"|'|--";
	protected static final String NX_FMT_STR = "str:%";
	protected static final String NX_CROSS_SITE_SCRIPTING = "rx:<|>|'|\\\"|;|\\(|\\)";
	protected static final String NX_EVAL_INJECTION = "str:;";
	protected static final String NX_OS_INJECTION = "rx:&|\\|;";
	protected static final String NX_HTTP_RESPONSE_SPLITTING = "rx:\n|\r";
	protected static final String NX_DIRECTORY_INDEXING = "rx:\n|\\$|\\?\r|/";

	protected static final Map<String, String> PAYLOAD_MAP_NAXSI = map(
			GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, NX_CROSS_SITE_SCRIPTING,
			GenericVulnerability.CWE_SQL_INJECTION, NX_SQL_INJECTION,
			GenericVulnerability.CWE_PATH_TRAVERSAL, NX_PATH_TRAVERSAL,
			GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, NX_HTTP_RESPONSE_SPLITTING,
			GenericVulnerability.CWE_XPATH_INJECTION, NX_XPATH_INJECTION,
			GenericVulnerability.CWE_BLIND_XPATH_INJECTION, NX_XPATH_INJECTION,
			GenericVulnerability.CWE_LDAP_INJECTION, NX_LDAP_INJECTION,
			GenericVulnerability.CWE_OS_COMMAND_INJECTION, NX_OS_INJECTION,
			GenericVulnerability.CWE_FORMAT_STRING_INJECTION, NX_FMT_STR,
			GenericVulnerability.CWE_EVAL_INJECTION, NX_EVAL_INJECTION,
			GenericVulnerability.CWE_DIRECT_REQUEST, NX_DIRECTORY_INDEXING,
			GenericVulnerability.CWE_DIRECTORY_INDEXING, NX_DIRECTORY_INDEXING
	);

	public NaxsiGenerator(){
		this.defaultDirective = "deny";
	}

	@Override
	public String[] getSupportedVulnerabilityTypes() {
		return PAYLOAD_MAP_NAXSI.keySet().toArray(new String[PAYLOAD_MAP_NAXSI.size()]);
	}
	
	@Override
	protected String generateRuleWithParameter(String uri, String action, String id, String genericVulnName, String parameter) {
		final String message = MESSAGE_MAP.get(genericVulnName);

		return String.format("BasicRule \"%s\" \"mz:$BODY_VAR:%s|$ARGS_VAR:%s\" %s %s;",
				PAYLOAD_MAP_NAXSI.get(genericVulnName), parameter, parameter, getActionString(action),
				getMessageString(id, message));
	}
	
	@Override
	protected String generateRuleWithPayloadInUrl(String uri, String action, String id, String genericVulnName) {
		final String message = MESSAGE_MAP.get(genericVulnName);

		return String.format("BasicRule \"str:%s\" \"mz:$URL:%s|URI\" %s;",
				uri, getActionString(action), getMessageString(id, message));
	}
	
	@Override
	protected String generateRuleForExactUrl(String uri, String action, String id, String genericVulnName) {
		final String message = MESSAGE_MAP.get(genericVulnName);

		return String.format("BasicRule \"str:%s\" \"mz:URL\" %s %s;",
				uri, getActionString(action), getMessageString(id, message));
	}

	/* This is a bit hackish: Java 7 doesn't support strings in switch-cases */
	private enum Decision { log, allow, deny, drop, sdrop }
	private String getActionString(String action) {
		final Decision decision = Decision.valueOf(action);
		switch (decision) {
			case log:
			case allow:
				return "\"s:LOG\"";
			case deny:
			case drop:
			case sdrop:
			default:/* if we don't know the action, drop. better safe than sorry ;) */
				return "\"s:DROP\"";
		}
	}

	private String getMessageString(String id, String genericVulnName) {
		return "id:" + id + " \"msg:" + genericVulnName + "\"";
	}
	
}