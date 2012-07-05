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
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * @author mcollins
 * 
 */
public class ImpervaSecureSphereGenerator extends RealTimeProtectionGenerator {
	
	// TODO move to more generic interface where host name is available.
	public static final String XML_START = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n" +
			"<vulnerabilities xmlns:msxsl=\"urn:schemas-microsoft-com:xslt\" " +
					"xmlns:theScript=\"urn:CustomScript\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchemainstance\">" +
			"<host host-name=\"10.1.1.230\">\n";
	
	public static final String XML_END = "</host></vulnerabilities>";
	
	// TODO look through CVEs in sm_schema_report_vulns.xsd
	private static final Map<String, String> VULN_TYPE_MAP = new HashMap<String, String>();
	static {
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY, "cross-site-request-forgery");
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "cross-site-scripting");
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_SQL_INJECTION, "sql-injection");
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_DIRECTORY_INDEXING, "directory-browsing");
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, "http-response-splitting");
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_LDAP_INJECTION, "ldap-injection");
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_PATH_TRAVERSAL, "directory-traversal");
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_EVAL_INJECTION, "remote-command-execution-env");
		VULN_TYPE_MAP.put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, "remote-command-execution-env");
	}
	
	private static final Map<String, String> VULN_SIGNATURE_MAP = new HashMap<String, String>();
	static {
		VULN_SIGNATURE_MAP.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "<\\%3C>\\%3E");
		VULN_SIGNATURE_MAP.put(GenericVulnerability.CWE_SQL_INJECTION, "' \\%27 \" \\%22 -- \\%2D\\%2D");
		VULN_SIGNATURE_MAP.put(GenericVulnerability.CWE_DIRECTORY_INDEXING, " %20 \\n $ \\? \\/\\? \\/\\n \\/$ \\/  \\/%20");
		VULN_SIGNATURE_MAP.put(GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, "%5cn %5cr %0d %0a");
		VULN_SIGNATURE_MAP.put(GenericVulnerability.CWE_LDAP_INJECTION, "\\\\ \\( \\) \\* \\%5c \\%2a \\%28 \\%29");
		VULN_SIGNATURE_MAP.put(GenericVulnerability.CWE_PATH_TRAVERSAL, "\\.\\\\ \\./ \\%2E\\\\ \\%2E/");
		VULN_SIGNATURE_MAP.put(GenericVulnerability.CWE_EVAL_INJECTION, "; \\%3b");
		VULN_SIGNATURE_MAP.put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, "& | ; %7C %26 %3B");
	}
	
	private static final Map<String, String> SEVERITIES_MAP = new HashMap<String, String>();
	static {
		SEVERITIES_MAP.put(GenericSeverity.CRITICAL, "high");
		SEVERITIES_MAP.put(GenericSeverity.HIGH, "high");
		SEVERITIES_MAP.put(GenericSeverity.MEDIUM, "medium");
		SEVERITIES_MAP.put(GenericSeverity.LOW, "low");
		SEVERITIES_MAP.put(GenericSeverity.INFO, "informative");
	}
	
	public ImpervaSecureSphereGenerator(WafRuleDao wafRuleDao, 
			WafRuleDirectiveDao wafRuleDirectiveDao) {
		this.wafRuleDao = wafRuleDao;
		this.wafRuleDirectiveDao = wafRuleDirectiveDao;
		this.defaultDirective = "-";
	}
	
	@Override
	public String[] getSupportedVulnerabilityTypes() {
		return VULN_TYPE_MAP.keySet().toArray(new String[] {});
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
		
		String signature = VULN_SIGNATURE_MAP.get(genericVulnName);
		
		// TODO test this rule generation
		if (genericVulnName != null && VULN_TYPE_MAP.keySet().contains(genericVulnName)) {
			StringBuilder sb = new StringBuilder();
			sb.append("\n<vulnerability id=\"" + id + "\" vuln-type=\"" + VULN_TYPE_MAP.get(genericVulnName) + 
									"\" severity=\"" + severity + "\">" +
					"\n    <source src-type=\"app-scan\" scan-id=\"" + scanId +"\"" +
								" scan-date=\"" + time + "\" src-reference=\"1\" />" +
					"\n    <parameters>" +
					"\n        <url>" + uri + "</url>");
			
			if (parameter != null && signature != null) {
				sb.append("\n        <param-name>" + parameter + "</param-name>" +
					"\n        <param-value>" + signature + "</param-value>");
			}
			
			sb.append("\n    </parameters>" +
					"\n</vulnerability>");
			
			return sb.toString();
		} else {
			return null;
		}
	}
}
