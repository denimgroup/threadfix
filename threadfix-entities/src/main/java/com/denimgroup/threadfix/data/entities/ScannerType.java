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

package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.CollectionUtils;

import java.util.Collections;
import java.util.List;

import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.*;

public enum ScannerType {

    ACUNETIX_WVS("acunetix", "Acunetix WVS","Acunetix WVS", ACUNETIX_WVS_DB_NAME, true),
    APPSCAN_DYNAMIC("appscan", APPSCAN_DYNAMIC_DB_NAME, "IBM Rational AppScan", APPSCAN_DYNAMIC_DB_NAME, true),
    ARACHNI("arachni", "Arachni", "Arachni", ARACHNI_DB_NAME),
    BRAKEMAN("brakeman", "Brakeman", "Brakeman", BRAKEMAN_DB_NAME),
    BURPSUITE("burp", BURPSUITE_DB_NAME,"Burp Suite", BURPSUITE_DB_NAME, true),
    CLANG("clang", "Clang","Clang", CLANG_DB_NAME),
	CPPCHECK("cppcheck", "Cppcheck","Cppcheck", CPPCHECK_DB_NAME),
    CAT_NET("catnet", "Microsoft CAT.NET", "Microsoft CAT.NET", CAT_NET_DB_NAME),
    PMD("pmd", "PMD", "PMD", PMD_DB_NAME),
    CENZIC_HAILSTORM("cenzic", CENZIC_HAILSTORM_DB_NAME, "Cenzic Hailstorm", CENZIC_HAILSTORM_DB_NAME),
    CHECKMARX("checkmarx", "CheckMarx", "CheckMarx", CHECKMARX_DB_NAME),
    DEPENDENCY_CHECK("dependencycheck", "Dependency Check", "Dependency Check", DEPENDENCY_CHECK_DB_NAME),
    FINDBUGS("findbugs", "FindBugs", "FindBugs", FINDBUGS_DB_NAME),
    FORTIFY("fortify", FORTIFY_DB_NAME, "Fortify 360", FORTIFY_DB_NAME),
    NESSUS("nessus", "Nessus", "Nessus", NESSUS_DB_NAME),
    APP_SPIDER("spider", APP_SPIDER_DB_NAME, "NTO Spider", APP_SPIDER_DB_NAME, true),
    NETSPARKER("netsparker", "Mavituna Security Netsparker", "Mavituna Security Netsparker", NETSPARKER_DB_NAME),
    SKIPFISH("skipfish", "Skipfish", "Skipfish", SKIPFISH_DB_NAME),
    W3AF("w3af", "w3af", "w3af", W3AF_DB_NAME),
    WEBINSPECT("webinspect", "WebInspect", "WebInspect", WEBINSPECT_DB_NAME, true),
    ZAPROXY("zap", "OWASP Zed Attack Proxy", "OWASP Zed Attack Proxy", ZAPROXY_DB_NAME, true),
    APPSCAN_SOURCE("appscansource", APPSCAN_SOURCE_DB_NAME, "IBM Rational AppScan Source Edition", APPSCAN_SOURCE_DB_NAME),
    APPSCAN_ENTERPRISE("appscanenterprise", APPSCAN_ENTERPRISE_DB_NAME, "IBM Rational AppScan Enterprise", APPSCAN_ENTERPRISE_DB_NAME),
    QUALYSGUARD_WAS("qualysguard", "QualysGuard WAS", "QualysGuard WAS", QUALYSGUARD_WAS_DB_NAME),
    SENTINEL("whitehat", "WhiteHat Sentinel", "WhiteHat Sentinel", SENTINEL_DB_NAME, "https://source.whitehatsec.com/site_vuln_detail.html"),
    SENTINEL_SOURCE("whitehatsource", "WhiteHat Sentinel Source", "WhiteHat Sentinel Source", SENTINEL_DB_NAME, "https://source.whitehatsec.com/application_findings_detail.html"),
    SSVL("ssvl", "SSVL", "SSVL", SSVL_DB_NAME),
    VERACODE("veracode", "Veracode", "Veracode", VERACODE_DB_NAME),
    MANUAL("manual", "Manual", "Manual", MANUAL_DB_NAME),
    CONTRAST("contrast", "Contrast", "Contrast", CONTRAST_DB_NAME),
    SONATYPE("sonatype", "Sonatype", "Sonatype", SONATYPE_DB_NAME),
    SCARF("scarf", SCARF_DB_NAME, SCARF_DB_NAME, SCARF_DB_NAME);

	public String displayName;
	private String shortName;
    private String oldName;
	private String dbName;
	private String baseUrl;
    private boolean supportedScanAgent;

	public String getDisplayName() {
		return this.displayName;
	}
	
	public String getShortName() {
		return this.shortName;
	}

    public String getOldName() {
        return oldName;
    }

    public String getDbName() {
        return this.dbName;
    }
    
    public String getBaseUrl() {
        return this.baseUrl;
    }

    public boolean getSupportedScanAgent() {
        return this.supportedScanAgent;
    }

    private ScannerType(String shortName, String displayName, String oldName, String dbName, boolean supportedScanAgent) {
        this.shortName = shortName;
        this.displayName = displayName;
        this.oldName = oldName;
        this.dbName = dbName;
        this.supportedScanAgent = supportedScanAgent;
    }

    private ScannerType(String shortName, String displayName, String oldName, String dbName, String baseUrl) {
        this.shortName = shortName;
        this.displayName = displayName;
        this.oldName = oldName;
        this.dbName = dbName;
        this.baseUrl = baseUrl;
    }

    private ScannerType(String shortName, String displayName, String oldName, String dbName) {
        this.shortName = shortName;
        this.displayName = displayName;
        this.oldName = oldName;
        this.dbName = dbName;
        this.baseUrl = "";
    }
	
	public static ScannerType getScannerType(String keyword) {
        if (keyword == null) {
            throw new IllegalArgumentException("Null passed to getScannerType");
        }

		ScannerType type = null;
		for (ScannerType t: values()) {
			if (keyword.equalsIgnoreCase(t.getShortName()) 
					|| keyword.equalsIgnoreCase(t.getDisplayName())
                    || keyword.equalsIgnoreCase(t.getDbName())
                    || keyword.equalsIgnoreCase(t.getOldName())) {
				type = t;
				break;
			}
		}
		return type;
	}
	
	public static String getShortName(String keyword) {
		for (ScannerType t: values()) {
			if (keyword.equalsIgnoreCase(t.getShortName()) 
					|| keyword.equalsIgnoreCase(t.getDisplayName())) {
				return t.getShortName();
			}
		}
		return null;
	}

    public static List<String> getScanAgentSupportedListInString() {
        List<String> result = CollectionUtils.list();
        for (ScannerType t: values()) {
            if (t.getSupportedScanAgent())
                result.add(t.getDisplayName());
        }
        Collections.sort(result);
        return result;
    }

    public static List<ScannerType> getScanAgentSupportedList() {
        List<ScannerType> result = CollectionUtils.list();
        for (ScannerType t: values()) {
            if (t.getSupportedScanAgent())
                result.add(t);
        }
        return result;
    }

    /**
     * This method to keep track of the date any Scanner Names being updated.
     * So that, when ThreadFix starts up, based on this date, ThreadFix will know whether it needs to update Scanner Names in database.
     * @return
     */
    public static String getEnumUpdatedDate(){
        return "2015-07-29 10:56";
    }
}