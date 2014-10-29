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

public enum ScannerType {
	ACUNETIX_WVS("acunetix", "Acunetix WVS", "Acunetix WVS"),
	APPSCAN_DYNAMIC("appscan", "IBM Rational AppScan", "IBM Rational AppScan"),
	ARACHNI("arachni", "Arachni", "Arachni"),
	BRAKEMAN("brakeman", "Brakeman", "Brakeman"),
	BURPSUITE("burp", "Burp Suite", "Burp Suite"),
	CAT_NET("catnet", "Microsoft CAT.NET", "Microsoft CAT.NET"),
    CENZIC_HAILSTORM("cenzic", "Cenzic Hailstorm", "Cenzic Hailstorm"),
    CHECKMARX("checkmarx", "CheckMarx", "CheckMarx"),
	DEPENDENCY_CHECK("dependencycheck", "Dependency Check", "Dependency Check"),
	FINDBUGS("findbugs", "FindBugs", "FindBugs"),
	FORTIFY("fortify", "Fortify 360", "Fortify 360"),
	NESSUS("nessus", "Nessus", "Nessus"),
	NTO_SPIDER("nto", "NTO Spider", "NTO Spider"),
	NETSPARKER("netsparker", "Mavituna Security Netsparker", "Mavituna Security Netsparker"),
	SKIPFISH("skipfish", "Skipfish", "Skipfish"),
	W3AF("w3af", "w3af", "w3af"),
	WEBINSPECT("webinspect", "WebInspect", "WebInspect"),
	ZAPROXY("zap", "OWASP Zed Attack Proxy", "OWASP Zed Attack Proxy"),
	APPSCAN_SOURCE("appscansource", "IBM Rational AppScan Source Edition", "IBM Rational AppScan Source Edition"),
	APPSCAN_ENTERPRISE("appscanenterprise", "IBM Rational AppScan Enterprise", "IBM Rational AppScan Enterprise"),
	QUALYSGUARD_WAS("qualysguard", "QualysGuard WAS", "QualysGuard WAS"),
	SENTINEL("whitehat", "WhiteHat Sentinel", "WhiteHat Sentinel"),
	VERACODE("veracode", "Veracode", "Veracode"),
	MANUAL("manual", "Manual", "Manual");

	private String fullName;
	private String shortName;
	private String dbName;

	public String getFullName() { 
		return this.fullName; 
	}
	
	public String getShortName() {
		return this.shortName;
	}

    public String getDbName() {
        return this.dbName;
    }

    private ScannerType(String shortName, String fullName, String dbName) {
        this.shortName = shortName;
        this.fullName = fullName;
        this.dbName = dbName;
    }
	
	public static ScannerType getScannerType(String keyword) {
		ScannerType type = null;
		for (ScannerType t: values()) {
			if (keyword.equalsIgnoreCase(t.getShortName()) 
					|| keyword.equalsIgnoreCase(t.getFullName())) {
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