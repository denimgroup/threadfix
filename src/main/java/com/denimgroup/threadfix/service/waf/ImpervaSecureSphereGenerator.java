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

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * @author mcollins
 * 
 */
public class ImpervaSecureSphereGenerator extends RealTimeProtectionGenerator {
	
	// TODO move to more generic interface where host name is available.
	public static final String XML_START = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>" +
			"<vulnerabilities xmlns:msxsl=\"urn:schemas-microsoft-com:xslt\" " +
					"xmlns:theScript=\"urn:CustomScript\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchemainstance\">" +
			"<host host-name=\"10.1.1.230\">";
	
	public static final String XML_END = "</host></vulnerabilities>";
	
	// TODO look through CVEs in sm_schema_report_vulns.xsd
	private static final Map<String, String> VULN_MAP = new HashMap<String, String>();
	static {
		VULN_MAP.put(GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY, "cross-site-request-forgery");
		VULN_MAP.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "cross-site-scripting");
		VULN_MAP.put(GenericVulnerability.CWE_SQL_INJECTION, "sql-injection");
		VULN_MAP.put(GenericVulnerability.CWE_DIRECTORY_INDEXING, "directory-browsing");
		VULN_MAP.put(GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, "http-response-splitting");
		VULN_MAP.put(GenericVulnerability.CWE_LDAP_INJECTION, "ldap-injection");
		VULN_MAP.put(GenericVulnerability.CWE_PATH_TRAVERSAL, "directory-traversal");
		VULN_MAP.put(GenericVulnerability.CWE_EVAL_INJECTION, "remote-command-execution-env");
		VULN_MAP.put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, "remote-command-execution-env");
	}
	
	private static final Map<String, String> SEVERITIES_MAP = new HashMap<String, String>();
	static {
		SEVERITIES_MAP.put(GenericSeverity.CRITICAL, "high");
		SEVERITIES_MAP.put(GenericSeverity.HIGH, "high");
		SEVERITIES_MAP.put(GenericSeverity.MEDIUM, "medium");
		SEVERITIES_MAP.put(GenericSeverity.LOW, "low");
		SEVERITIES_MAP.put(GenericSeverity.INFO, "informative");
	}
	
	public ImpervaSecureSphereGenerator(WafRuleDao wafRuleDao) {
		this.wafRuleDao = wafRuleDao;
		this.defaultDirective = "-";
	}
	
	@Override
	public String[] getSupportedVulnerabilityTypes() {
		return VULN_MAP.keySet().toArray(new String[] {});
	}
	
	// TODO update for scan IDs / dates
	@Override
	protected String generateRuleText(String genericVulnName, String uri, String action, 
			String id, String parameter, Vulnerability vuln) {
		
		String scanId = "0";
		if (vuln != null && vuln.getOriginalFinding() != null && 
				vuln.getOriginalFinding().getScan() != null &&
				vuln.getOriginalFinding().getScan().getId() != null) {
			scanId = vuln.getOriginalFinding().getScan().getId().toString();
		}
		
		String severity = "low";
		if (vuln != null && vuln.getGenericSeverity() != null && vuln.getGenericSeverity().getName() != null) {
			severity = SEVERITIES_MAP.get(vuln.getGenericSeverity().getName());
		}
		
		Calendar calendarToUse = Calendar.getInstance();
		if (vuln != null && vuln.getOriginalFinding() != null && 
				vuln.getOriginalFinding().getScan() != null &&
				vuln.getOriginalFinding().getScan().getImportTime() != null) {
			calendarToUse = vuln.getOriginalFinding().getScan().getImportTime();
		}
		String time = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(calendarToUse.getTime());
		
		if (genericVulnName != null && VULN_MAP.keySet().contains(genericVulnName)) {
			return "<vulnerability id=\"" + id + "\" vuln-type=\"" + VULN_MAP.get(genericVulnName) + 
									"\" severity=\"" + severity + "\">" +
						"<source src-type=\"ThreadFix\" scan-id=\"" + scanId +"\"" +
								"scan-date=\"" + time + "\" src-reference=\"1\" />" +
						"<parameters>" +
							"<url>" + uri + "</url>" +
							"<param-name>" + parameter + "</param-name>" +
						"</parameters>" +
					"</vulnerability>";
		} else {
			return null;
		}
	}
}
