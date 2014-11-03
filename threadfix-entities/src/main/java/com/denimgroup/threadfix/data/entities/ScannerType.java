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

package com.denimgroup.threadfix.data.entities;

import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.*;

public enum ScannerType {
    ACUNETIX_WVS("acunetix", "Acunetix WVS", ACUNETIX_WVS_DB_NAME),
    APPSCAN_DYNAMIC("appscan", "IBM Rational AppScan", APPSCAN_DYNAMIC_DB_NAME),
    ARACHNI("arachni", "Arachni", ARACHNI_DB_NAME),
    BRAKEMAN("brakeman", "Brakeman", BRAKEMAN_DB_NAME),
    BURPSUITE("burp", "Burp Suite", BURPSUITE_DB_NAME),
    CLANG("clang", "Clang", CLANG_DB_NAME),
	CPPCHECK("cppcheck", "Cppcheck", CPPCHECK_DB_NAME),
    CAT_NET("catnet", "Microsoft CAT.NET", CAT_NET_DB_NAME),
    PMD("pmd", "PMD", PMD_DB_NAME),
    CENZIC_HAILSTORM("cenzic", "Cenzic Hailstorm", CENZIC_HAILSTORM_DB_NAME),
    CHECKMARX("checkmarx", "CheckMarx", CHECKMARX_DB_NAME),
    DEPENDENCY_CHECK("dependencycheck", "Dependency Check", DEPENDENCY_CHECK_DB_NAME),
    FINDBUGS("findbugs", "FindBugs", FINDBUGS_DB_NAME),
    FORTIFY("fortify", "Fortify SCA", FORTIFY_DB_NAME),
    NESSUS("nessus", "Nessus", NESSUS_DB_NAME),
    NTO_SPIDER("nto", "NTO Spider", NTO_SPIDER_DB_NAME),
    NETSPARKER("netsparker", "Mavituna Security Netsparker", NETSPARKER_DB_NAME),
    SKIPFISH("skipfish", "Skipfish", SKIPFISH_DB_NAME),
    W3AF("w3af", "w3af", W3AF_DB_NAME),
    WEBINSPECT("webinspect", "WebInspect", WEBINSPECT_DB_NAME),
    ZAPROXY("zap", "OWASP Zed Attack Proxy", ZAPROXY_DB_NAME),
    APPSCAN_SOURCE("appscansource", "IBM Rational AppScan Source Edition", APPSCAN_SOURCE_DB_NAME),
    APPSCAN_ENTERPRISE("appscanenterprise", "IBM Rational AppScan Enterprise", APPSCAN_ENTERPRISE_DB_NAME),
    QUALYSGUARD_WAS("qualysguard", "QualysGuard WAS", QUALYSGUARD_WAS_DB_NAME),
    SENTINEL("whitehat", "WhiteHat Sentinel", SENTINEL_DB_NAME, "https://source.whitehatsec.com/site_vuln_detail.html"),
    SSVL("ssvl", "SSVL", SSVL_DB_NAME),
    VERACODE("veracode", "Veracode", VERACODE_DB_NAME),
    MANUAL("manual", "Manual", MANUAL_DB_NAME);

	private String fullName;
	private String shortName;
	private String dbName;
	private String baseUrl;

	public String getFullName() { 
		return this.fullName; 
	}
	
	public String getShortName() {
		return this.shortName;
	}

    public String getDbName() {
        return this.dbName;
    }
    
    public String getBaseUrl() {
        return this.baseUrl;
    }

    private ScannerType(String shortName, String fullName, String dbName, String baseUrl) {
        this.shortName = shortName;
        this.fullName = fullName;
        this.dbName = dbName;
        this.baseUrl = baseUrl;
    }

    private ScannerType(String shortName, String fullName, String dbName) {
        this.shortName = shortName;
        this.fullName = fullName;
        this.dbName = dbName;
        this.baseUrl = "";
    }
	
	public static ScannerType getScannerType(String keyword) {
		ScannerType type = null;
		for (ScannerType t: values()) {
			if (keyword.equalsIgnoreCase(t.getShortName()) 
					|| keyword.equalsIgnoreCase(t.getFullName())
                    || keyword.equalsIgnoreCase(t.getDbName())) {
				type = t;
				break;
			}
		}
		return type;
	}
	
	public static String getShortName(String keyword) {
		for (ScannerType t: values()) {
			if (keyword.equalsIgnoreCase(t.getShortName()) 
					|| keyword.equalsIgnoreCase(t.getFullName())) {
				return t.getShortName();
			}
		}
		return null;
	}
}