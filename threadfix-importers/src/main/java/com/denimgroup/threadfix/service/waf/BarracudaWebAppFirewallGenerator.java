package com.denimgroup.threadfix.service.waf;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.list;

import java.text.MessageFormat;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringEscapeUtils;

import com.denimgroup.threadfix.annotations.WebApplicationFirewall;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;

/**
 * author: dsavelski, Barracuda Networks
 */
@WebApplicationFirewall(name = WafType.BARRACUDA_WAF)
public class BarracudaWebAppFirewallGenerator extends RealTimeProtectionGenerator {
	
	private static final String DEFAULT_REMEDY = "";

	private static final Map<String, String> VULN_TYPE_REMEDY_MAP = map(
		 
			//OS
			GenericVulnerability.CWE_EVAL_INJECTION, "__os_command_injection_parameter",
			GenericVulnerability.CWE_OS_COMMAND_INJECTION, "__os_command_injection_parameter",
			"Improper Neutralization of Special Elements used in a Command ('Command Injection')", "__os_command_injection_parameter",
			
			//SQL
			GenericVulnerability.CWE_SQL_INJECTION, "__sql_injection_parameter",
			"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "__sql_injection_parameter",
			
			//RFI
			"Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')", "__remote_file_inclusion_parameter",
			"URL Redirection to Untrusted Site ('Open Redirect')", "__remote_file_inclusion_parameter" ,
			
			//XSS
			GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "__xss_parameter",
			"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "__xss_parameter",

			GenericVulnerability.CWE_DIRECTORY_INDEXING, "__data_theft_directory_indexing",
			"Exposure of Backup File to an Unauthorized Control Sphere","__local_adr_deny_rule",
			
			//OTHERS
			GenericVulnerability.CWE_PATH_TRAVERSAL, "__directory_traversal_parameter",
			GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, "__param_response_splitting",
			GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY, "__csrf_in_url",
			
			"Improper Restriction of Excessive Authentication Attempts", "__param_brute_force",
			"Response Discrepancy Information Exposure","__param_brute_force",	
			
			"Information Exposure Through an Error Message", "__data_theft_errors_on_page",
			"Protection Mechanism Failure", "__clickjacking",
			"File and Directory Information Exposure", "__local_adr_deny_rule",
			"Sensitive Cookie in HTTPS Session Without 'Secure' Attribute","__cookie_secure"
			);

	private static final Map<String, String> SEVERITIES_MAP = map(
			GenericSeverity.CRITICAL, "High",
			GenericSeverity.HIGH, "High", 
			GenericSeverity.MEDIUM, "Medium", 
			GenericSeverity.LOW, "Low",
			GenericSeverity.INFO, "Informational");
	
	private static Map<String, Integer> RECOMMENDATIONS_MAP = map();

	public BarracudaWebAppFirewallGenerator() {
		this.defaultDirective = "none";
	}
	
	@Override
	protected String[] getSupportedVulnerabilityTypes() {
		//SHOULD NO BE USED ANYMORE after overiding makeRule()
		return VULN_TYPE_REMEDY_MAP.keySet().toArray(new String[] {});
	}
	
	public static String getStart(List<WafRule> rules) {
		if (rules == null || rules.size() == 0) {
			 return null;
		}

		RECOMMENDATIONS_MAP.clear();
		
		String xml_host="", xml_duration="0:0:0.0";
		int info_vuls=0, triv_vuls=0, medium_vuls=0, high_vuls=0;

		int recommendation_fix_id=0;
		List<String> recs = list();
		List<String> issues = list();
		
        for (WafRule rule : rules) {
        	if (rule == null || rule.getRule() == null || rule.getVulnerability() == null 
        			|| rule.getVulnerability().getSurfaceLocation() == null) {
				 continue;
			}
        	
        	Vulnerability vul = rule.getVulnerability();
        	SurfaceLocation surf = vul.getSurfaceLocation();

			String parameter = rule.getParameter();
        	
			if ("".equals(xml_host) && rule.getVulnerability() != null &&
        			rule.getVulnerability().getSurfaceLocation() != null && 
        			rule.getVulnerability().getSurfaceLocation().getHost() != null && 
        			rule.getVulnerability().getSurfaceLocation().getProtocol() != null) {
        		
        		SurfaceLocation tmp_sl = rule.getVulnerability().getSurfaceLocation();
        		xml_host = StringEscapeUtils.escapeXml11(tmp_sl.getProtocol() + "://" + tmp_sl.getHost());
        	}

        	// Count for the XML info
        	String severity = SEVERITIES_MAP.get(rule.getVulnerability().getGenericSeverity().getName());
        	if (severity == "High") {
        		high_vuls++;
        	}else if(severity == "Medium") {
        		medium_vuls++;
        	}else if(severity == "Low") {
        		triv_vuls++;
        	}else if(severity == "Informational") {
        		info_vuls++;
        	}else{
        		System.out.println("BarracudaWebFirewallGenerator.getStart(): Unknown Severity: " + severity + " in rule: " + rule);
        	}
        	
        	String rule_recommandation = rule.getVulnerability().getOriginalFinding().getScannerRecommendation();
        	if (! RECOMMENDATIONS_MAP.containsKey(rule_recommandation)) {
        		RECOMMENDATIONS_MAP.put(rule_recommandation, recommendation_fix_id);
        		
        		recs.add("    <recommendation id=\"fix_" + RECOMMENDATIONS_MAP.get(rule_recommandation) + "\">" +
        				StringEscapeUtils.escapeXml11(rule_recommandation) + "</recommendation>\n");
        		
        		recommendation_fix_id++;
        	}

        	String issue = generateIssue(vul.getGenericVulnerability().getName(), surf.getPath(), null, rule.getNativeId(), parameter, vul);
        	issues.add(issue + "\n");
        }
        
        StringBuffer buffer = new StringBuffer(MessageFormat.format(BWFStrings.XML_DOC_START, xml_host, xml_duration, 
        		rules.size(), info_vuls, triv_vuls, medium_vuls ,high_vuls));
        
        for (String s: recs)
        	buffer.append(s);
        
        buffer.append(BWFStrings.XML_ISSUES_START);
        
        for (String s: issues)
        	buffer.append(s);
        
        return buffer.toString();
    }

    public static String getEnd(List<WafRule> rules) {
    	return BWFStrings.XML_DOC_END;
    }
    
    @Override
    protected WafRule makeRule(Integer currentId, Vulnerability vulnerability, WafRuleDirective directive) {
    	// We generate all the rules in getStart() because there is information in beginning of XML that depends on rules (Such as recommendation)
    	if (currentId == null || vulnerability == null 
				|| vulnerability.getSurfaceLocation() == null
				|| vulnerability.getGenericVulnerability() == null
				|| vulnerability.getGenericVulnerability().getName() == null) {
			return null;
		}
    	
    	String remedy_for_waf = VULN_TYPE_REMEDY_MAP.get(vulnerability.getGenericVulnName());
		if (remedy_for_waf == null)
			remedy_for_waf = DEFAULT_REMEDY;
		
		//Generate fake/comment rule. Reason: rule can't be empty later on.
		String rule = "    <!-- vul " + currentId + " : " + vulnerability.getVulnerabilityName()
		+ ", CWE: " + vulnerability.getGenericVulnerability().getCweId()  + ", REMEDY: " + remedy_for_waf + " -->";
		WafRule newRule = new WafRule();
		newRule.setRule(rule);
		newRule.setNativeId(currentId.toString());
		return newRule;
    }
    
    protected static String generateIssue(String genericVulnName, String uri, String action, String id, String parameter,
    		Vulnerability vuln) {
    	
    	String vulDesc = "";
		if (vuln != null && uri != null && vuln.getOriginalFinding() != null
				&& vuln.getOriginalFinding().getScan() != null && vuln.getOriginalFinding().getScannerDetail() != null) {
			
			vulDesc = StringEscapeUtils.escapeXml11(vuln.getOriginalFinding().getScannerDetail());
			
			if (vulDesc == null)
				vulDesc = "";
		}

		String severity = "Informational";
		if (vuln != null && vuln.getGenericSeverity() != null && vuln.getGenericSeverity().getName() != null) {
			severity = SEVERITIES_MAP.get(vuln.getGenericSeverity().getName());
		}

		if (genericVulnName != null) {
			String entity_param = "", entity_type= "";

			if (parameter == null && vuln.getSurfaceLocation().getParameter() != null && !vuln.getSurfaceLocation().getParameter().isEmpty())
					parameter = vuln.getSurfaceLocation().getParameter().replaceFirst("param=", "");
			
			// URL & Parameter
			if (parameter != null && !parameter.isEmpty()) {
				entity_param = parameter;
				entity_type = "Parameter";
			}
			
			String handled = "no";
			String remedy_for_waf = VULN_TYPE_REMEDY_MAP.get(vuln.getGenericVulnName());
			if (remedy_for_waf == null)
				remedy_for_waf = DEFAULT_REMEDY;
			else
				handled = "yes";
			
			String recommendationId = "0000" + id;

			String recommandation = vuln.getOriginalFinding().getScannerRecommendation();
			if (RECOMMENDATIONS_MAP.containsKey(recommandation))
				recommendationId = RECOMMENDATIONS_MAP.get(recommandation).toString();
			
			String variantId = id;
			String url_humanized = vuln.getSurfaceLocation().getHumanLocation();
			String attack_vector = StringEscapeUtils.escapeXml11(vuln.getOriginalFinding().getAttackString());
			
			String confidence = "";
			if (vuln.getOriginalFinding().getConfidenceRating() != null)
				confidence = "" + vuln.getOriginalFinding().getConfidenceRating();
			
			String cwe = "";
			if (vuln.getGenericVulnerability().getCweId() != null)
				cwe = "CWE-" + vuln.getGenericVulnerability().getCweId();
			
			if (attack_vector==null)
				attack_vector = "";
			
			String rule_text = MessageFormat.format(BWFStrings.XML_ISSUE_TEMPLATE, 
					genericVulnName, handled, id, severity, cwe, confidence, url_humanized,
					entity_param, entity_type, recommendationId, variantId, 
					attack_vector, vulDesc, remedy_for_waf);

			return rule_text;
		} else {
			System.out.println("BNVLMWAFGenerator.generateRuleText() -> Error: returning NULL");
			return null;
		}
    	
    }
	
	private class BWFStrings {
		static final String XML_DOC_START = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
				"\n<va-engine-result>" + 
				"\n  <scannerInfo>" + 
				"\n    <product>Barracuda Vulnerability Manager</product>" +
				"\n    <version>1.0</version>" +
				"\n  </scannerInfo>" +
				"\n  <scanSummary>" +
				"\n    <websitesScanned>" + 
				"\n      <host name=\"{0}\">" +                 				// {0} host
				"\n        <scanDuration>{1}</scanDuration>" +					// {1} scan duration
				"\n        <totalIssues>{2}</totalIssues>" +					// {2} total
				"\n        <informativeIssues>{3}</informativeIssues>" +		// {3} informative
				"\n        <trivialIssues>{4}</trivialIssues>" +				// {4} trivial
				"\n        <mediumSeverityIssues>{5}</mediumSeverityIssues>" +	// {5} medium
				"\n        <highSeverityIssues>{6}</highSeverityIssues>" +		// {6} high
				"\n      </host>" +
				"\n    </websitesScanned>" +
				"\n  </scanSummary>" +
				"\n  <recommendations>" + 
				"\n";
		
		static final String XML_ISSUES_START = "\n  </recommendations>\n  <issues>";
		
		static final String XML_ISSUE_TEMPLATE = "\n    <issue IssueId=\"{0}\" IssueName=\"{0}\" handled=\"{1}\"" +		// {0}, {1}
		        " sequenceId=\"{2}\" severity=\"{3}\">" +					// {2}, {3}
				"\n      <information>" +
				"\n        <domain/>" +
				"\n        <cwe>{4}</cwe>" +								// {4} cwe
				"\n        <confidence>{5}</confidence>" + 					// {5} confidence
				"\n        <url>{6}</url>" +								// {6} url 
				"\n        <entity_name>{7}</entity_name>" +				// {7} parameter name
				"\n        <entity_type>{8}</entity_type>" +				// {8} type
				"\n        <recommendationId>fix_{9}</recommendationId>" +	// {9} recommendation
				"\n        <variants>" +
				"\n          <variant variantId=\"var_{10}\">" +			// {10} variant
				"\n            <attackVector>{11}</attackVector>" +			// {11} attack vector
				"\n            <description>{12}</description>" +			// {12} description
				"\n            <additionalInformation/>" +
				"\n          </variant>" +
				"\n        </variants>" +
				"\n      </information>" +
				"\n      <remedy>" + 
				"\n        <id>{13}</id>" + 								// {13} barracuda waf remedy id
				"\n        <description/>" + 
				"\n      </remedy>" +
				"\n    </issue>";
		
		static final String XML_DOC_END = "\n  </issues>\n  <return-code>0</return-code>\n</va-engine-result>\n";
		
	}
}
