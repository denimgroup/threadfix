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
//     Contributor(s): Riverbed Technology
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.waf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringEscapeUtils;

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

/**
 * @author Mirko Dziadzka @ Riverbed
 * 
 */
public class RiverbedWebAppFirewallGenerator extends RealTimeProtectionGenerator {	
       public static String RULE_PROVIDER_NAME = "threadfix"; 
       public static String RULE_PROVIDER_VERSION = "20140915";
	
        protected static final Map<String, String> VULNERABILITY_CLASS_MAPPING = new HashMap<String,String>(){
            {
                // XSS
                put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "GENERIC_CROSS_SITE_SCRIPTING");
                // injections
                put(GenericVulnerability.CWE_SQL_INJECTION, "GENERIC_SQL_INJECTION");
                put(GenericVulnerability.CWE_LDAP_INJECTION, "GENERIC_LDAP_INJECTION");
                put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, "GENERIC_COMMAND_INJECTION");
                // path problems
                put(GenericVulnerability.CWE_PATH_TRAVERSAL, "GENERIC_PATH_TRAVERSAL");
                put(GenericVulnerability.CWE_DIRECTORY_INDEXING, "GENERIC_DIRECTORY_INDEXING");
            }
        };

	public RiverbedWebAppFirewallGenerator(WafRuleDao wafRuleDao, WafRuleDirectiveDao wafRuleDirectiveDao) {
		this.wafRuleDao = wafRuleDao;
		this.wafRuleDirectiveDao = wafRuleDirectiveDao;
	}
	
	@Override
	public String[] getSupportedVulnerabilityTypes() {
		return new String[] { 
                                GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
				GenericVulnerability.CWE_SQL_INJECTION, 
				//GenericVulnerability.CWE_DIRECT_REQUEST,
				GenericVulnerability.CWE_PATH_TRAVERSAL,
				//GenericVulnerability.CWE_XPATH_INJECTION,
				GenericVulnerability.CWE_DIRECTORY_INDEXING,
				GenericVulnerability.CWE_LDAP_INJECTION,
				GenericVulnerability.CWE_OS_COMMAND_INJECTION,
				//GenericVulnerability.CWE_FORMAT_STRING_INJECTION,
				//GenericVulnerability.CWE_EVAL_INJECTION  
                                };
	}

        public static String getStart(List<WafRule> rules) {
                return "{\"provider\":\"" + RULE_PROVIDER_NAME + "\",\"version\":\""+ RULE_PROVIDER_VERSION +"\",\"rules\":[\n";
        }

        public static String getEnd(List<WafRule> rules) {
                // add empty element to list of protection rules
                return "\tnull]\n}\n";
        }

	


	@Override
	protected String generateRuleWithParameter(String uri, String action, String id,
			String genericVulnName, String parameter) {
                JsonObject res = new JsonObject();

                res.addProperty("match", "args");
                res.addProperty("uri", uri);
                res.addProperty("action", action);
                res.addProperty("id", id);
                res.addProperty("genericVulnName", VULNERABILITY_CLASS_MAPPING.get(genericVulnName));
                res.addProperty("parameter", parameter);

                return "\t" + res.toString() + ",";
	}
	
	@Override
	protected String generateRuleWithPayloadInUrl(String uri, String action, String id,
			String genericVulnName) {

                JsonObject res = new JsonObject();

                res.addProperty("match", "uri");
                res.addProperty("uri", uri);
                res.addProperty("action", action);
                res.addProperty("id", id);
                res.addProperty("genericVulnName", VULNERABILITY_CLASS_MAPPING.get(genericVulnName));

                return "\t" + res.toString() + ",";
		
	}
	
	@Override
	protected String generateRuleForExactUrl(String uri, String action, String id,
			String genericVulnName) {


                JsonObject res = new JsonObject();

                res.addProperty("match", "uri");
                res.addProperty("uri", uri);
                res.addProperty("action", action);
                res.addProperty("id", id);
                res.addProperty("genericVulnName", VULNERABILITY_CLASS_MAPPING.get(genericVulnName));

                return "\t" + res.toString() + ",";
	}
	
}
