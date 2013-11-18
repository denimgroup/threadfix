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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;

/**
 * This class uses a different system for generating rules because 
 * BIG-IP accepts a large policy XML that is a combination of rules instead of
 * standalone rules like mod_security or Snort do.
 * <br><br>
 * 
 * @author mcollins
 *
 */
public class BigIPASMGenerator extends RealTimeProtectionGenerator {
	
	//TODO change structure of getStart / getEnd here and in other classes
	
	public BigIPASMGenerator(WafRuleDao wafRuleDao, WafRuleDirectiveDao wafRuleDirectiveDao) {
		this.wafRuleDao = wafRuleDao;
		this.wafRuleDirectiveDao = wafRuleDirectiveDao;
		defaultDirective = "transparent";
	}
	
	/**
	 * This map is used to skip a lot of if/then statements when selecting a set of attack signatures.
	 */
	private static Map<String, String[]> vulnTypeSignatureMap = new HashMap<>();
	static {
		vulnTypeSignatureMap.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, BigIPStrings.SIGS_XSS);
		vulnTypeSignatureMap.put(GenericVulnerability.CWE_PATH_TRAVERSAL, BigIPStrings.SIGS_PATH_TRAVERSAL);
		vulnTypeSignatureMap.put(GenericVulnerability.CWE_SQL_INJECTION, BigIPStrings.SIGS_SQLI);
		vulnTypeSignatureMap.put(GenericVulnerability.CWE_XPATH_INJECTION, BigIPStrings.SIGS_XPATH);
		vulnTypeSignatureMap.put(GenericVulnerability.CWE_BLIND_XPATH_INJECTION, BigIPStrings.SIGS_XPATH);
		vulnTypeSignatureMap.put(GenericVulnerability.CWE_FILE_UPLOAD, BigIPStrings.SIGS_FILE_UPLOAD);
	}
	
	private static Map<String, String> vulnTypeSigSetMap = new HashMap<>();
	static {
		vulnTypeSigSetMap.put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "299999994");
		vulnTypeSigSetMap.put(GenericVulnerability.CWE_PATH_TRAVERSAL, "299999990");
		vulnTypeSigSetMap.put(GenericVulnerability.CWE_SQL_INJECTION, "299999994");
		vulnTypeSigSetMap.put(GenericVulnerability.CWE_XPATH_INJECTION, "299999989");
		vulnTypeSigSetMap.put(GenericVulnerability.CWE_BLIND_XPATH_INJECTION, "299999989");
	}

	@Override
	public String[] getSupportedVulnerabilityTypes() {
		return new String[] { 
				GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
				GenericVulnerability.CWE_PATH_TRAVERSAL,
				GenericVulnerability.CWE_SQL_INJECTION,
				GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY,
				GenericVulnerability.CWE_XPATH_INJECTION,
				GenericVulnerability.CWE_BLIND_XPATH_INJECTION,
				GenericVulnerability.CWE_INFORMATION_EXPOSURE,
				GenericVulnerability.CWE_PRIVACY_VIOLATION,
				GenericVulnerability.CWE_FILE_UPLOAD,
				GenericVulnerability.CWE_GENERIC_INJECTION,
				GenericVulnerability.CWE_DEBUG_CODE
				
		};
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
		
		//CSRF is handled on a by-url basis in its own tag
		if (GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY.equals(vulnType)) {
			rule.setVulnerabilityDesc("CSRF");
			rule.setRule("<csrf_urls>" + path + "</csrf_urls>");
			return rule;
		}
		
		// Possibly turn on Response Scrubbing if CCN or SSN might be present
		if (GenericVulnerability.CWE_INFORMATION_EXPOSURE.equals(vulnType) ||
				GenericVulnerability.CWE_PRIVACY_VIOLATION.equals(vulnType)) {
			for (Finding finding : vulnerability.getFindings()) {
				if (finding != null && finding.getChannelVulnerability() != null && 
						finding.getChannelVulnerability().getName()!= null &&
						(finding.getChannelVulnerability().getName().contains("Credit Card") ||
						 finding.getChannelVulnerability().getName().contains("Social Security"))) {
					rule.setRule("Response Scrubbing");
					return rule;
				}
			}
			return null;
		}
		
		// Possibly turn on Illegal methods
		// TODO improve detection of these vulns
		if (GenericVulnerability.CWE_GENERIC_INJECTION.equals(vulnType) ||
				GenericVulnerability.CWE_DEBUG_CODE.equals(vulnType)) {
			for (Finding finding : vulnerability.getFindings()) {
				if (finding != null && finding.getChannelVulnerability() != null && 
						finding.getChannelVulnerability().getName()!= null &&
						finding.getChannelVulnerability().getName().contains("HTTP Method")) {
					rule.setRule("Illegal Method");
					return rule;
				}
			}
			return null;
		}

		// The general case: set the path, parameter, and type
		if (path != null && (parameter != null || GenericVulnerability.CWE_FILE_UPLOAD.equals(vulnType))) {
			rule.setParameter(parameter);
			rule.setPath(path);
			rule.setRule("BIG-IP");
			rule.setVulnerabilityDesc(vulnType);
			return rule;
		}
		
		return null;
	}

	/**
	 * Generate the first part of the policy.
	 * 
	 * The general strategy is to compose a non-repeating structure of URL/param pairs,
	 * keeping track of corresponding attack signatures and combining them if necessary,
	 * then expanding that into the policy string using string templates.
	 * <br/><br/>
	 * Non-attack signature related rules are handled separately, adding to the length and
	 * complexity of this method.
	 * 
	 * TODO split into smaller methods
	 * @param rules
	 * @return
	 */
	public static String getStart(List<WafRule> rules) { 
		 if (rules == null || rules.size() == 0) {
			 return null;
		 }
		 String directive = null;
		 
		 StringBuilder csrfStrings =  new StringBuilder();
		 List<String> csrfStringList = new ArrayList<>();
		 
		 StringBuilder ruleTextBuilder = new StringBuilder();
		 
		 // First keys are paths
		 // Second keys are parameters
		 // Set<String> values are the signatures
		 Map<String, Map<String, Set<String>>> ruleMap = 
			 new HashMap<>();
		 Map<String, String> dateMap = new HashMap<>();
		 
		 boolean directoryTraversalsOn = false;
		 boolean responseScrubbingOn = false;
		 boolean illegalMethodOn = false;
		 
		 // Construct the map<string, map<string, set<string>>> structure
		 for (WafRule rule : rules) {
			 if (rule == null || rule.getRule() == null) {
				 continue;
			 }
			 
			 // get values from rule
			 String path = rule.getPath();
			 String parameter = rule.getParameter();
			 String[] attackSignatures = vulnTypeSignatureMap.get(rule.getVulnerabilityDesc());

			 SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			 
			 String date = null;
			 if (rule.getCreatedDate() != null) {
				 date = dateFormatter.format(rule.getCreatedDate());
			 } else {
				 date = dateFormatter.format(Calendar.getInstance().getTime());
			 }
			 
			 // Add the entry
			 if (path != null && parameter != null) {
				 if (ruleMap.get(path) == null) {
					 if (date == null) {
						 date = dateFormatter.format(Calendar.getInstance().getTime());
					 }
					 dateMap.put(path, date);
					 
					 Map<String, Set<String>> entry = new HashMap<>();
					 ruleMap.put(path, entry);
				 }
				 
				 if (ruleMap.get(path).get(parameter) == null) {
					 ruleMap.get(path).put(parameter, new TreeSet<String>());
				 }
				 
				 if (attackSignatures != null && attackSignatures.length > 0) {
					 ruleMap.get(path).get(parameter)
					 	.addAll(Arrays.asList(attackSignatures));
				 }
			 }
			 
			 if (directive == null && rule != null && 
					 rule.getWafRuleDirective() != null) {
				 directive = rule.getWafRuleDirective().getDirective();
			 }
			 
			 // check for any of the special cases
			 if (rule != null && rule.getVulnerabilityDesc() != null &&
					 rule.getVulnerabilityDesc().startsWith("CSRF")) {
				 csrfStringList.add(rule.getRule());
			 } else if (!directoryTraversalsOn && 
					 rule != null && rule.getVulnerabilityDesc() != null &&
					 rule.getVulnerabilityDesc()
					 	.equals(GenericVulnerability.CWE_PATH_TRAVERSAL)) {
				 directoryTraversalsOn = true;
			 } else if (!responseScrubbingOn &&
					 rule.getRule().equals("Response Scrubbing")) {
				 responseScrubbingOn = true;
			 } else if (!illegalMethodOn &&
					 rule.getRule().equals("Illegal Method")) {
				 illegalMethodOn = true;
			 }
		 }
		 
		 Collections.sort(csrfStringList);
		 
		 for (String rule : csrfStringList) {
			 csrfStrings.append("\n    ").append(rule);
		 }
		 		 
		 // this does the expansion of the big data structure
		 expandRules(ruleMap, dateMap, ruleTextBuilder);
			 
		 StringBuilder start = new StringBuilder();
		 
		 // handle special cases and expand the rest of the policy
		 String directoryTraversal = directoryTraversalsOn ? "enabled" : "disabled";
		 String responseScrubbing = responseScrubbingOn ? "true" : "false";
		 String illegalMethod = illegalMethodOn ? "true" : "false";
		 
		 if (csrfStrings.length() == 0) {
			 start.append(BigIPStrings.XML_START_BEFORE_CSRF)
			 	  .append(BigIPStrings.XML_START_AFTER_CSRF
			 	  	.replaceFirst("\\{directive\\}", directive)
			 	  	.replaceAll("\\{responseScrubbing\\}", responseScrubbing))
			 	  .append(BigIPStrings.XML_START_CSRF_DISABLED);
		 } else {
			 start.append(BigIPStrings.XML_START_BEFORE_CSRF)
				  .append(csrfStrings.toString())
				  .append(BigIPStrings.XML_START_AFTER_CSRF
					.replaceFirst("\\{directive\\}", directive)
					.replaceAll("\\{responseScrubbing\\}", responseScrubbing))
				  .append(BigIPStrings.XML_START_CSRF_ENABLED);
		 }
		 
		 SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		 
		 start.append(BigIPStrings.XML_START_FINAL
				 			.replaceAll("\\{date\\}", 
				 					dateFormatter.format(Calendar.getInstance().getTime()))
				 			.replaceAll("\\{directoryTraversal\\}", directoryTraversal)
				 			.replaceAll("\\{illegalMethod\\}", illegalMethod)
			 				);
		 start.append(ruleTextBuilder);
		 
		 return start.toString();
	}
	
	/**
	 * Take the map structure that is constructed and append all of the rule text
	 * onto the supplied StringBuilder
	 * @param ruleMap
	 * @param dateMap
	 * @param ruleTextBuilder
	 */
	private static void expandRules(Map<String, Map<String, Set<String>>> ruleMap, 
			Map<String, String> dateMap, StringBuilder ruleTextBuilder) {
		if (ruleMap == null || dateMap == null || ruleTextBuilder == null) {
			return;
		}
	
		for (Entry<String, Map<String, Set<String>>> entry : ruleMap.entrySet()) {
			if (entry == null) {
				continue;
			}
			 
			String date = dateMap.get(entry.getKey());
			 
			ruleTextBuilder.append(BigIPStrings.TEMPLATE_URL
					 				.replaceFirst("\\{path\\}", entry.getKey())
					 				.replaceFirst("\\{date\\}", date));
			 
			for (Entry<String, Set<String>> paramEntry : entry.getValue().entrySet()) {
				ruleTextBuilder.append(BigIPStrings.TEMPLATE_PARAM
						 			.replaceFirst("\\{parameter\\}", paramEntry.getKey())
						 			.replaceFirst("\\{date\\}", date));
				 
				for (String attackSignature : paramEntry.getValue()) {
					ruleTextBuilder.append(BigIPStrings.TEMPLATE_ATTACK_SIGNATURE
							 		.replaceFirst("\\{signatureNumber\\}", attackSignature));
				}
				 
				ruleTextBuilder.append(BigIPStrings.TEMPLATE_PARAM_END);
			}
			 
			ruleTextBuilder.append(BigIPStrings.TEMPLATE_URL_END);
		}
	}

	public static String getEnd(List<WafRule> rules) { 
		if (rules == null || rules.size() == 0) {
			 return null;
		}
		
		// using a set ensures that we don't include the same signature set 
		// more than one time. 
		Set<String> signatureSet =  new TreeSet<>();
				 
		for (WafRule rule : rules) {
			if (rule != null && rule.getVulnerability() != null &&
					rule.getVulnerability().getGenericVulnerability() != null &&
					rule.getVulnerability().getGenericVulnerability().getName() != null &&
					vulnTypeSigSetMap.get(rule.getVulnerability()
							.getGenericVulnerability().getName()) != null) {
				signatureSet.add(vulnTypeSigSetMap.get(rule.getVulnerability()
						.getGenericVulnerability().getName()));
			}
		}

		String signatureString = "";
		if (signatureSet.size() > 0) {
			StringBuilder signatures = new StringBuilder();
			 
			for (String signature : signatureSet) {
				signatures.append(BigIPStrings.TEMPLATE_SIGNATURE_SET.replaceFirst("\\{id\\}", signature));
			}
			
			signatureString = signatures.toString();
		}
		
		//  Java complains about super long strings, so I cut it into pieces.
		return BigIPStrings.XML_END_BEFORE_SIGNATURES +
			   signatureString + 
			   BigIPStrings.XML_AFTER_SIGNATURES_1 +
			   BigIPStrings.XML_AFTER_SIGNATURES_2 +
			   BigIPStrings.XML_AFTER_SIGNATURES_3 +
			   BigIPStrings.XML_AFTER_SIGNATURES_4 +
			   BigIPStrings.XML_AFTER_SIGNATURES_5 +
			   BigIPStrings.XML_AFTER_SIGNATURES_6;
	}

}
