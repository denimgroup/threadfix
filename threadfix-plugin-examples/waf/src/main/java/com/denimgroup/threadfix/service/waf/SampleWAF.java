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
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;

/**
 * Created by mcollins on 3/2/15.
 */
@WebApplicationFirewall(name = "Sample WAF")
public class SampleWAF extends RealTimeProtectionGenerator {

    @Override
    protected String[] getSupportedVulnerabilityTypes() {
        return new String[]{
                GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
                GenericVulnerability.CWE_SQL_INJECTION,
                GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY,
                // any other valid CWE name
                // there are also other fields in GenericVulnerability
                GenericVulnerability.CWE_DIRECT_REQUEST
        };
    }

    @Override
    protected String[] getVulnerabilitiesWithParameters() {
        return new String[]{
                // these are the types that go to the generation method with parameters
                GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
                GenericVulnerability.CWE_SQL_INJECTION
        };
    }

    @Override
    protected String generateRuleWithParameter(String uri, String directive, String id, String genericVulnName, String parameter) {
        // directive comes from the user in the UI
        // ignore if you don't need it

        // ID is for internal tracking

        // the uri and parameter are for filtering
        // the generic vuln is so you know how to identify the request as malicious

        // see examples in Snort, mod_security, etc.

        return "rule-string-" + id; // the finished rule
    }

    @Override
    protected String[] getVulnerabilitiesWithPayloadInUrl() {
        return new String[] {
                // GET Requests, generally
             GenericVulnerability.CWE_CROSS_SITE_REQUEST_FORGERY
        };
    }

    @Override
    protected String generateRuleWithPayloadInUrl(String uri, String action, String id, String genericVulnName) {

        // same as generateRuleWithParameter except the payload will be in the URL

        return "rule-string-payload-url-" + id;
    }

    @Override
    protected String[] getVulnerabilitiesAtExactUrl() {
        return new String[] {
                // this allows the WAF integration to block all requests to a url
                GenericVulnerability.CWE_DIRECT_REQUEST
        };
    }

    @Override
    protected String generateRuleForExactUrl(String uri, String action, String id, String genericVulnName) {
        // same as other methods but just blocks a url


        return "rule-string-exact-url-" + id;
    }

    @Override
    protected WafRule makeRule(Integer currentId, Vulnerability vulnerability, WafRuleDirective directive) {
        // this method allows more control over creation of WafRule objects

        // you can either implement this method or the methods above
        return super.makeRule(currentId, vulnerability, directive);
    }
}