////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import com.denimgroup.threadfix.data.entities.*;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Map.Entry;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * @author mcollins
 * 
 */
@WebApplicationFirewall(name = WafType.IMPERVA_SECURE_SPHERE)
public class ImpervaSecureSphereGenerator extends RealTimeProtectionGenerator {
	
	// TODO look through CVEs in sm_schema_report_vulns.xsd
	private static final Map<String, String> VULN_TYPE_MAP = map(
			GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY, "cross-site-request-forgery",
			GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "cross-site-scripting",
			GenericVulnerability.CWE_SQL_INJECTION, "sql-injection",
			GenericVulnerability.CWE_DIRECTORY_INDEXING, "directory-browsing",
			GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, "http-response-splitting",
			GenericVulnerability.CWE_PATH_TRAVERSAL, "directory-traversal",
			GenericVulnerability.CWE_EVAL_INJECTION, "remote-command-execution-env",
			GenericVulnerability.CWE_OS_COMMAND_INJECTION, "remote-command-execution-env"
		);
		
	private static final Map<String, String> SEVERITIES_MAP = map(
			GenericSeverity.CRITICAL, "high",
			GenericSeverity.HIGH, "high",
			GenericSeverity.MEDIUM, "medium",
			GenericSeverity.LOW, "low",
			GenericSeverity.INFO, "informative"
		);
	
	public ImpervaSecureSphereGenerator() {
		this.defaultDirective = "-";
	}
	
	@Override
	public String[] getSupportedVulnerabilityTypes() {
		return VULN_TYPE_MAP.keySet().toArray(new String[] {});
	}
	
	// TODO update for scan IDs / dates
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
		
		if (genericVulnName != null && VULN_TYPE_MAP.keySet().contains(genericVulnName)) {
			StringBuilder sb = new StringBuilder();
			sb.append("\n<vulnerability id=\"" + id + "\" vuln-type=\"" + VULN_TYPE_MAP.get(genericVulnName) + 
									"\" severity=\"" + severity + "\">" +
					"\n    <source src-type=\"ThreadFix\" scan-id=\"" + scanId +"\"" +
								" scan-date=\"" + time + "\" src-reference=\"13\" />" +
					"\n    <parameters>" +
					"\n        <url>" + uri + "</url>");
			
			if (parameter != null) {
				sb.append("\n        <param-name>" + parameter + "</param-name>");
			}
			
			sb.append("\n    </parameters>" +
					"\n</vulnerability>");
			
			return sb.toString();
		} else {
			return null;
		}
	}
	
	@Override
	protected WafRule makeRule(Integer currentId, Vulnerability vulnerability, WafRuleDirective directive) {
		if (currentId == null || vulnerability == null 
				|| vulnerability.getSurfaceLocation() == null
				|| vulnerability.getGenericVulnerability() == null
				|| vulnerability.getGenericVulnerability().getName() == null) {
			return null;
		}
		
		SurfaceLocation surfaceLocation = vulnerability.getSurfaceLocation();
	
		String vulnType = vulnerability.getGenericVulnerability().getName();
		// Check if the vuln is supported
		if (!stringInList(vulnType, getSupportedVulnerabilityTypes())) {
			return null;
		}
		
		String parameter = surfaceLocation.getParameter();
		String path      = surfaceLocation.getPath();
		
		WafRule rule = new WafRule();
		rule.setIsNormalRule(false);
		rule.setWafRuleDirective(directive);
		rule.setNativeId(currentId.toString());
		rule.setRule(generateRuleText(vulnerability.getGenericVulnerability().getName(),
				path,null,currentId.toString(),parameter,vulnerability));
		
		return rule;
	}

	public static String getEnd(List<WafRule> rules) {
		return "</vulnerabilities>";
	}

	public static String getStart(List<WafRule> rules) {
		StringBuilder builder = new StringBuilder();
		
		builder.append("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n" +
			"<vulnerabilities xmlns:msxsl=\"urn:schemas-microsoft-com:xslt\" " +
					"xmlns:theScript=\"urn:CustomScript\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchemainstance\">\n");
		
		if (rules == null || rules.size() == 0) {
			return builder.toString();
		}
		
		Map<String, List<WafRule>> hostRuleMap = map();
		
		for (WafRule rule : rules) {
			String key = null;
			if (rule != null && rule.getVulnerability() != null 
					&& rule.getVulnerability().getSurfaceLocation() != null 
					&& rule.getVulnerability().getSurfaceLocation().getHost() != null) {
				key = rule.getVulnerability().getSurfaceLocation().getHost();
			} else if (rule != null) {
				key = "127.0.0.1";
			}
			
			if (key != null) {
				if (hostRuleMap.get(key) == null) {
					hostRuleMap.put(key, new ArrayList<WafRule>());
				}
				
				hostRuleMap.get(key).add(rule);
			}
		}
		
		for (Entry<String, List<WafRule>> entry : hostRuleMap.entrySet()) {
			if (entry != null) {
				builder.append("<host host-name=\"" + entry.getKey() + "\">\n");
				for (WafRule rule : entry.getValue()) {
					builder.append(rule.getRule());
				}
				builder.append("\n</host>\n");
			}
		}
		
		return builder.toString();
	}
}
