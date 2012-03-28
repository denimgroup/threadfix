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

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;

/**
 * @author mcollins
 * 
 */
public class DenyAllRWebGenerator extends RealTimeProtectionGenerator {

	public static final String XML_START = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
												"<eaccess>";
	public static final String XML_END = "</eaccess>";
	
	public DenyAllRWebGenerator(WafRuleDao wafRuleDao) {
		this.wafRuleDao = wafRuleDao;//return returnString;
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

		// TODO make sure the >< characters are filtered.
		payload = payload.replace(";", "\\;");
		payload = payload.replace(">", "%gt;");
		payload = payload.replace("<", "%lt;");
		payload = payload.replace("&", "&amp;");

		return "<rules title=\"" + genericVulnName + "\" uid=\"" + id + "\">\n" +
					"<rule action=\"" + action + "\" part=\"uri\">\n" +
						"<pattern groups=\"OnlyIfUri.php\" pid=\"" + id + "\">\"-ie2: " + uri + ".*" +
								parameter + "=.*(" + payload + ")\"</pattern>\n" +
					"</rule>\n" +
				"</rules>\n";
	}
	
	@Override
	protected String generateRuleForExactUrl(String uri, String action,
			String id, String genericVulnName) {
		
		return "<rules title=\"" + genericVulnName + "\" uid=\"" + id + "\">\n" +
					"<rule action=\"" + action + "\" part=\"uri\">\n" +
						"<pattern groups=\"OnlyIfUri.php\" pid=\"" + id + "\">\"-ie2: " + uri + "\"</pattern>\n" +
					"</rule>\n" +
				"</rules>\n";
	}

	@Override
	protected String generateRuleWithPayloadInUrl(String uri, String action,
			String id, String genericVulnName) {
		
		String payload = PAYLOAD_MAP.get(genericVulnName);

		payload = payload.replace(";", "\\;");
		payload = payload.replace(">", "%gt;");
		payload = payload.replace("<", "%lt;");
		payload = payload.replace("&", "&amp;");
		
		return "<rules title=\"" + genericVulnName + "\" uid=\"" + id + "\">\n" +
					"<rule action=\"" + action + "\" part=\"uri\">\n" +
						"<pattern groups=\"OnlyIfUri.php\" pid=\"" + id + "\">\"-ie2: " + 
							uri + ".*" +".*(" + payload + ")\"</pattern>\n" +
					"</rule>\n" +
				"</rules>\n";
	}
}
