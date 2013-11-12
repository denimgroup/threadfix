package com.denimgroup.threadfix.data.entities;

public enum ScannerType {
	ACUNETIX_WVS("acunetix", "Acunetix WVS"),
	APPSCAN_DYNAMIC("appscan", "IBM Rational AppScan"),
	ARACHNI("arachni", "Arachni"),
	BRAKEMAN("brakeman", "Brakeman"),
	BURPSUITE("burp", "Burp Suite"),
	CAT_NET("catnet", "Microsoft CAT.NET"),
	DEPENDENCY_CHECK("dependencycheck", "Dependency Check"),
	FINDBUGS("findbugs", "FindBugs"),
	FORTIFY("fortify", "Fortify 360"),
	NESSUS("nessus", "Nessus"),
	NTO_SPIDER("nto", "NTO Spider"),
	NETSPARKER("netsparker", "Mavituna Security Netsparker"),
	SKIPFISH("skipfish", "Skipfish"),
	W3AF("w3af", "w3af"),
	WEBINSPECT("webinspect", "WebInspect"),
	ZAPROXY("zap", "OWASP Zed Attack Proxy"),
	APPSCAN_SOURCE("appscansource", "IBM Rational AppScan Source Edition"),
	APPSCAN_ENTERPRISE("appscanenterprise", "IBM Rational AppScan Enterprise"),
	QUALYSGUARD_WAS("qualysguard", "QualysGuard WAS"),
	SENTINEL("whitehat", "WhiteHat Sentinel"),
	VERACODE("veracode", "Veracode"),
	MANUAL("manual", "Manual");

	private String fullName;
	private String shortName;
	
	public String getFullName() { 
		return this.fullName; 
	}
	
	public String getShortName() {
		return this.shortName;
	}
	
	private ScannerType(String shortName, String fullName) { 
		this.shortName = shortName;
		this.fullName = fullName;
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