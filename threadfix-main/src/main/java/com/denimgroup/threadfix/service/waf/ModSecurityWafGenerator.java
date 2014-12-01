////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.annotations.WebApplicationFirewall;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.WafType;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@WebApplicationFirewall(name = WafType.MOD_SECURITY)
public class ModSecurityWafGenerator extends RealTimeProtectionGenerator {	
	public static final String RULE_START_URI = "SecRule REQUEST_URI \"^";
	
	public static final String MOD_SECURITY_PATH_TRAVERSAL = ".|\\%2e";
	
	public ModSecurityWafGenerator(){
		this.defaultDirective = "deny";
		PAYLOAD_MAP.put(GenericVulnerability.CWE_PATH_TRAVERSAL, MOD_SECURITY_PATH_TRAVERSAL);
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
				GenericVulnerability.CWE_EVAL_INJECTION  };
	}
	
	@Override
	protected String generateRuleWithParameter(String uri, String action, String id,
			String genericVulnName, String parameter) {
		
		String payload = PAYLOAD_MAP.get(genericVulnName);
		String message = MESSAGE_MAP.get(genericVulnName);
		
		return RULE_START_URI + pcreRegexEscape(uri) + "\""
			+ "\"phase:2,chain," + action + ",msg:'" + message + ": " + uri
			+ " [" + parameter + "]',id:'" + id + "',severity:'2'\"\n"
			+ "SecRule ARGS:" + parameter + " \"" + payload + "\"\n";
	}
	
	@Override
	protected String generateRuleWithPayloadInUrl(String uri, String action, String id,
			String genericVulnName) {

		String payload = PAYLOAD_MAP.get(genericVulnName);
		String message = MESSAGE_MAP.get(genericVulnName);
		
		return RULE_START_URI + pcreRegexEscape(uri) + "[^?]*(" + payload + ")\""
			+ "\"phase:2," + action + ",msg:'" + message + ": " + uri
			+ "',id:'" + id + "',severity:'2'\"\n";
	}
	
	@Override
	protected String generateRuleForExactUrl(String uri, String action, String id,
			String genericVulnName) {

		String payload = PAYLOAD_MAP.get(genericVulnName);
		String message = MESSAGE_MAP.get(genericVulnName);
		
		return RULE_START_URI + pcreRegexEscape(uri) + "(" + payload + ")"
			+ "\"\"phase:2," + action + ",msg:'" + message + ": " + uri
			+ "',id:'" + id + "',severity:'2'\"\n";
	}
	
}