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

package com.denimgroup.threadfix.selenium.tests;

import java.util.HashMap;
import java.util.Map;


public class ScanContents extends BaseIT {

	public final static Map<String, String> SCAN_FILE_MAP = new HashMap<>();
	static {
		SCAN_FILE_MAP.put("Microsoft CAT.NET", getScanFilePath("Static","CAT.NET","catnet_RiskE.xml") );
		SCAN_FILE_MAP.put("FindBugs", getScanFilePath("Static","FindBugs","findbugs-normal.xml") );
		SCAN_FILE_MAP.put("IBM Rational AppScan", getScanFilePath("Dynamic","AppScan","appscan-php-demo.xml") );
		SCAN_FILE_MAP.put("Mavituna Security Netsparker", getScanFilePath("Dynamic","NetSparker","netsparker-demo-site.xml") );
		SCAN_FILE_MAP.put("Skipfish", getScanFilePath("Dynamic","Skipfish","skipfish-demo-site.zip") );
		SCAN_FILE_MAP.put("w3af", getScanFilePath("Dynamic","w3af","w3af-demo-site.xml") );
		SCAN_FILE_MAP.put("OWASP Zed Attack Proxy", getScanFilePath("Dynamic","ZAP","zaproxy-normal.xml") );
		SCAN_FILE_MAP.put("Nessus", getScanFilePath("Dynamic","Nessus","nessus_report_TFTarget.xml") );
		SCAN_FILE_MAP.put("Arachni", getScanFilePath("Dynamic","Arachni","php-demo.xml") );
		SCAN_FILE_MAP.put("WebInspect",getScanFilePath("Dynamic","WebInspect","webinspect-demo-site.xml"));
		SCAN_FILE_MAP.put("NTO Spider",getScanFilePath("Dynamic","NTOSpider","VulnerabilitiesSummary.xml"));
		SCAN_FILE_MAP.put("NTO Spider6", getScanFilePath("Dynamic","NTOSpider","VulnerabilitiesSummary6.xml"));
		SCAN_FILE_MAP.put("Brakeman", getScanFilePath("Static","Brakeman","brakeman.json")); 
		SCAN_FILE_MAP.put("Fortify 360", getScanFilePath("Static","Fortify","ZigguratUtility.fpr"));
		SCAN_FILE_MAP.put("Acunetix WVS", getScanFilePath("Dynamic","Acunetix","testaspnet.xml"));
		SCAN_FILE_MAP.put("Burp Suite", getScanFilePath("Dynamic","Burp","burp-demo-site.xml"));
		SCAN_FILE_MAP.put("IBM Rational AppScan Source Edition", null);
        SCAN_FILE_MAP.put("DependencyCheck",getScanFilePath("Static","dependencycheck","dependency-check-report.xml"));
        SCAN_FILE_MAP.put("Unmapped Scan", getScanFilePath("UnmappedFindings", "results", "unmapped.xml"));
        SCAN_FILE_MAP.put("Snort Log", getScanFilePath("Realtime", "Snort", "snort_log.txt"));
        SCAN_FILE_MAP.put("AppScanEnterprise", getScanFilePath("Dynamic", "AppScanEnterprise", "Application_Security_Issues.xml"));
        SCAN_FILE_MAP.put("Old ZAP Scan", getScanFilePath("Dynamic","ZAP","smallpetclinic.xml"));
        SCAN_FILE_MAP.put("New ZAP Scan", getScanFilePath("Dynamic","ZAP","largepetclinic.xml"));
        SCAN_FILE_MAP.put("CPP Scan", getScanFilePath("Static","cppcheck","cppcheckScan.xml"));
	}

    public static String getScanFilePath(String scannerName) {
        return SCAN_FILE_MAP.get(scannerName);
    }

    public static String getScanFilePath() {
        return SCAN_FILE_MAP.get("Acunetix WVS");
    }
	
	private static String getScanFilePath(String category, String scannerName, String fileName) {
        String fileSeparator = System.getProperty("file.separator");
		String string = "SupportingFiles"+ fileSeparator + category  + fileSeparator + scannerName +
                fileSeparator + fileName;
		String urlFromCommandLine = System.getProperty("scanFileBaseLocation");
		if (urlFromCommandLine != null) {
			return urlFromCommandLine + string;
		}
		return ScanContents.class.getClassLoader().getResource(string).getPath();
	}
	

	
}
