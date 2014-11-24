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

import com.denimgroup.threadfix.annotations.WebApplicationFirewall;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafType;
import com.google.gson.JsonObject;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Mirko Dziadzka, Riverbed Technology
 *
 */
@WebApplicationFirewall(name = WafType.RIVERBED_WEB_APP_FIREWALL)
public class RiverbedWebAppFirewallGenerator extends RealTimeProtectionGenerator {

    public static String RULE_PROVIDER_NAME = "threadfix";
    public static String RULE_PROVIDER_VERSION = "20140915";
    protected static final Map<String, String> VULNERABILITY_CLASS_MAPPING = new HashMap<String, String>() {
        {
            // XSS
            put(GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, "GENERIC_CROSS_SITE_SCRIPTING");
            // injections
            put(GenericVulnerability.CWE_BLIND_XPATH_INJECTION, "GENERIC_BLIND_XPATH_INJECTION");
            put(GenericVulnerability.CWE_EVAL_INJECTION, "GENERIC_EVAL_INJECTION");
            put(GenericVulnerability.CWE_FORMAT_STRING_INJECTION, "GENERIC_FORMAT_STRING_INJECTION");
            put(GenericVulnerability.CWE_GENERIC_INJECTION, "GENERIC_INJECTION");
            put(GenericVulnerability.CWE_LDAP_INJECTION, "GENERIC_LDAP_INJECTION");
            put(GenericVulnerability.CWE_OS_COMMAND_INJECTION, "GENERIC_COMMAND_INJECTION");
            put(GenericVulnerability.CWE_SQL_INJECTION, "GENERIC_SQL_INJECTION");
            put(GenericVulnerability.CWE_XPATH_INJECTION, "GENERIC_XPATH_INJECTION");
            // path problems
            put(GenericVulnerability.CWE_PATH_TRAVERSAL, "GENERIC_PATH_TRAVERSAL");
            put(GenericVulnerability.CWE_DIRECTORY_INDEXING, "GENERIC_DIRECTORY_INDEXING");
            // server (we can't handle this in the first implementation)
            put(GenericVulnerability.CWE_HTTP_RESPONSE_SPLITTING, "GENERIC_RESPONSE_SPLITTING");
            put(GenericVulnerability.CWE_DIRECT_REQUEST, "GENERIC_DIRECT_REQUEST");
            put(GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY, "GENERIC_CSRF");
            put(GenericVulnerability.CWE_FILE_UPLOAD, "GENERIC_FILE_UPLOAD");
            // response problems
            put(GenericVulnerability.CWE_INFORMATION_EXPOSURE, "GENERIC_INFORMATION_EXPOSURE");
            put(GenericVulnerability.CWE_PRIVACY_VIOLATION, "GENERIC_PRIVACY_VIOLATION");
            put(GenericVulnerability.CWE_DEBUG_CODE, "GENERIC_DEBUG_CODE");
        }
    };

    @Override
    public String[] getSupportedVulnerabilityTypes() {
        return new String[]{
            //xss 
            GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
            // injection
            GenericVulnerability.CWE_BLIND_XPATH_INJECTION,
            GenericVulnerability.CWE_EVAL_INJECTION,
            GenericVulnerability.CWE_FORMAT_STRING_INJECTION,
            GenericVulnerability.CWE_GENERIC_INJECTION,
            GenericVulnerability.CWE_LDAP_INJECTION,
            GenericVulnerability.CWE_OS_COMMAND_INJECTION,
            GenericVulnerability.CWE_SQL_INJECTION,
            GenericVulnerability.CWE_XPATH_INJECTION, 
        };
    }

    public static String getStart(List<WafRule> rules) {
        return "{\"provider\":\"" + RULE_PROVIDER_NAME + "\",\"version\":\"" + RULE_PROVIDER_VERSION + "\",\"rules\":[\n";
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
