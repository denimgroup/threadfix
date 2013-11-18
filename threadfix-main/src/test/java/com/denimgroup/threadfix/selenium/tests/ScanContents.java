package com.denimgroup.threadfix.selenium.tests;

import java.util.HashMap;
import java.util.Map;


public class ScanContents extends BaseTest{
	public ScanContents(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}

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
		SCAN_FILE_MAP.put("Burp Suite", getScanFilePath("Dynamic","Burp","burp-demo-site.xml") );
		SCAN_FILE_MAP.put("IBM Rational AppScan Source Edition", null);
	}
	

	
	public final static String[][] catnetResults = {
			{ XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "email"},
			{ XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "txtMessage"},
			{ XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "txtSubject"},
			{ XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
			{ XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
			{ XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtCardNumber"},
			{ XSS, "Critical", "/ZigguratUtilityWeb/Message.aspx", "Msg"},
			{ SQLI, "Critical", "/ZigguratUtilityWeb/LoginPage.aspx", "txtPassword"},
			{ SQLI, "Critical", "/ZigguratUtilityWeb/LoginPage.aspx", "txtUsername"},
			{ SQLI, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
			{ SQLI, "Critical", "/ZigguratUtilityWeb/ViewStatement.aspx", "StatementID"},
		};
	
	public final static String[][] findBugsResults = new String[][] {
			{ XSS, "Critical", "securibench/micro/aliasing/Aliasing1.java", "name"},
			{ XSS, "Critical", "securibench/micro/aliasing/Aliasing4.java", "name"},
			{ XSS, "Critical", "securibench/micro/basic/Basic1.java", "str"},
			{ XSS, "Critical", "securibench/micro/basic/Basic18.java", "s"},
			{ XSS, "Critical", "securibench/micro/basic/Basic2.java", "str"},
			{ XSS, "Critical", "securibench/micro/basic/Basic28.java", "name"},
			{ XSS, "Critical", "securibench/micro/basic/Basic4.java", "str"},
			{ XSS, "Critical", "securibench/micro/basic/Basic8.java", "str"},
			{ XSS, "Critical", "securibench/micro/basic/Basic9.java", "s1"},
			{ XSS, "Critical", "securibench/micro/pred/Pred4.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred5.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred6.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred7.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred8.java", "name"},
			{ XSS, "Critical", "securibench/micro/pred/Pred9.java", "name"},
			{ XSS, "Critical", "securibench/micro/session/Session1.java", "name"},
			{ XSS, "Critical", "securibench/micro/session/Session2.java", "name"},
			{ XSS, "High", "securibench/micro/basic/Basic10.java", "s5"},
			{ XSS, "High", "securibench/micro/basic/Basic27.java", ""},
			{ XSS, "High", "securibench/micro/basic/Basic29.java", ""},
			{ XSS, "High", "securibench/micro/basic/Basic30.java", ""},
			{ XSS, "High", "securibench/micro/basic/Basic32.java", "header"},
			{ XSS, "High", "securibench/micro/basic/Basic34.java", "headerValue"},
			{ XSS, "High", "securibench/micro/basic/Basic35.java", ""},
			{ XSS, "High", "securibench/micro/pred/Pred2.java", "name"},
			{ XSS, "High", "securibench/micro/pred/Pred3.java", "name"},
			{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates3.java", ""},
			{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates4.java", ""},
			{ XSS, "High", "securibench/micro/strong_updates/StrongUpdates5.java", ""},
			{ SQLI, "High", "securibench/micro/basic/Basic19.java", ""},
			{ SQLI, "High", "securibench/micro/basic/Basic20.java", ""},
			{ SQLI, "High", "securibench/micro/basic/Basic21.java", ""},
		};
	
	public final static String[][] ibmAppScanResults = new String[][] {
			{ PATH_TRAVERSAL, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
			{ XSS, "Critical", "/demo/EvalInjection2.php", "command"},
			{ XSS, "Critical", "/demo/XPathInjection2.php", ""},
			{ XSS, "Critical", "/demo/XPathInjection2.php", "password"},
			{ XSS, "Critical", "/demo/XPathInjection2.php", "username"},
			{ XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
			{ COMMAND_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
			{ SQLI, "Critical", "/demo/XPathInjection2.php", "password"},
			{ SQLI, "Critical", "/demo/XPathInjection2.php", "username"},
			{ INFO_EXPOSURE_ERROR_MESSAGE, "Critical", "/demo/SQLI2.php", "username"},
			{ GENERIC_INJECTION, "Medium", "/demo/XPathInjection2.php", "password"},
			{ GENERIC_INJECTION, "Medium", "/demo/XPathInjection2.php", "username"},
			{ GENERIC_INJECTION, "Medium", "/demo/XSS-reflected2.php", "username"},
			{ DIRECTORY_LISTING, "Medium", "/demo/DIRECT~1/", ""},
			{ DIRECTORY_LISTING, "Medium", "/demo/DirectoryIndexing/", ""},
			{ REFLECTION_ATTACK, "Medium", "/demo/XPathInjection2.php", "password"},
			{ REFLECTION_ATTACK, "Medium", "/demo/XPathInjection2.php", "username"},
			{ REFLECTION_ATTACK, "Medium", "/demo/XSS-reflected2.php", "username"},
			{ FORCED_BROWSING, "Low", "/demo/DIRECT~1/", ""},
			{ FORCED_BROWSING, "Low", "/demo/DirectoryIndexing/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/aux/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/cgi-bin/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/com1/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/com2/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/com3/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/aux/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com1/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com2/", ""},
			{ IMPROPER_INPUT_VALIDATION, "Low", "/demo/com3/", ""},
			{ INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", ""},
			{ INFORMATION_EXPOSURE, "Low", "/demo/PredictableResource.php", ""},
			{ INFORMATION_EXPOSURE, "Low", "/demo/XSS-cookie.php", ""},
			{ INFO_LEAK_COMMENTS, "Low", "/demo/", ""},
			{ INFO_LEAK_COMMENTS, "Low", "/demo/SQLI.php", ""},
			{ INFO_LEAK_COMMENTS, "Low", "/demo/XSS-reflected.php", ""},
			{ INFO_LEAK_COMMENTS, "Low", "/demo/XSS-reflected2.php", ""},
			{ INFO_LEAK_TEST_CODE, "Low", "/", ""},
			{ INFO_LEAK_TEST_CODE, "Low", "/demo/PredictableResource.php", ""},
			{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/EvalInjection2.php", "command"},
			{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/LDAPInjection2.php", "username"},
			{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/SQLI2.php", "username"},
			{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/XPathInjection2.php", "password"},
			{ INFO_LEAK_SERVER_ERROR, "Info", "/demo/XPathInjection2.php", "username"},
	};
	
	public final static String[][] netsparkerResults = new String[] [] {
			{CODE_INJECTION, "Critical", "/demo/EvalInjection2.php", "command"},
			{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
			{RESOURCE_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
			{XSS, "High", "/demo/EvalInjection2.php", "command"},
			{XSS, "High", "/demo/SQLI2.php", "username"},
			{XSS, "High", "/demo/XPathInjection2.php", "password"},
			{XSS, "High", "/demo/XPathInjection2.php", "username"},
			{XSS, "High", "/demo/XSS-reflected2.php", "username"},
			{SOURCE_CODE_INCLUDE, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
			{CONFIGURATION, "Low", "/demo/", ""},
			{FORCED_BROWSING, "Low", "/demo/LDAPInjection.php", ""},
			{FORCED_BROWSING, "Low", "/demo/PredictableResource.php.bak", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/PredictableResource.php", ""},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Low", "/demo/SQLI2.php", "username"},
			{INFORMATION_EXPOSURE, "Info", "/demo/EvalInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/demo/FormatString2.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/demo/LDAPInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/demo/OSCommandInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/demo/PathTraversal.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/demo/SQLI2.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/demo/XPathInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/demo/XSS-cookie.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/demo/XSS-reflected2.php", ""},
			{"Information Exposure Through Directory Listing", "Info", "/demo/DirectoryIndexing/", ""},
	};
	
	public final static String[][] skipfishResults = new String [][] {
			{SQLI, "Critical", "/demo/EvalInjection2.php", "command"},
			{SQLI, "Critical", "/demo/LDAPInjection2.php", "username"},
			{SQLI, "Critical", "/demo/SQLI2.php", "username"},
			{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/EvalInjection2.php","command"},
			{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/FormatString2.php","name"},
			{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/PathTraversal.php","action"},
			{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/XSS-cookie.php","cookie"},
			{IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/XSS-reflected2.php","username"},
			{PATH_TRAVERSAL, "High", "/demo/PathTraversal.php","action"},
			{XSS, "High", "/demo/XSS-cookie.php","cookie"},
			{XSS, "High", "/demo/XSS-reflected2.php","username"},
			{DIRECTORY_LISTING, "High", "/demo/DirectoryIndexing/",""},
			{INFO_LEAK_SERVER_ERROR, "High", "/demo/SQLI2.php","username"},
			{CSRF, "Medium", "/demo/EvalInjection2.php",""},
			{CSRF, "Medium", "/demo/FormatString2.php",""},
			{CSRF, "Medium", "/demo/LDAPInjection2.php",""},
			{CSRF, "Medium", "/demo/OSCommandInjection2.php",""},
			{CSRF, "Medium", "/demo/SQLI2.php",""},	
			{CSRF, "Medium", "/demo/XSS-cookie.php",""},
			{CSRF, "Medium", "/demo/XSS-reflected2.php",""},
		
	};
	
	
	public final static String[][] ntospiderResults = new String [][] {
			{"Improper Authentication", "Critical", "/bank/login.aspx", ""},
			{"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/bank/login.aspx", "passw"},
			{"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/bank/login.aspx", "uid"},
			{"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/subscribe.aspx", "txtEmail"},
			{"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "High", "/bank/login.aspx", "uid"},
			{"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "High", "/comment.aspx", "name"},
			{"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "High", "/notfound.aspx", "aspxerrorpath"},
			{"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "High", "/search.aspx", "txtSearch"},
			{"Information Exposure Through Directory Listing", "Medium", "/bank/", ""},
			{"Privacy Violation", "Medium", "/", ""},
			{"Privacy Violation", "Medium", "/bank/login.aspx", ""},
			{"Privacy Violation", "Medium", "/comment.aspx", ""},
			{"Privacy Violation", "Medium", "/default.aspx", ""},
			{"Privacy Violation", "Medium", "/disclaimer.htm", ""},
			{"Privacy Violation", "Medium", "/feedback.aspx", ""},
			{"Privacy Violation", "Medium", "/notfound.aspx", ""},
			{"Privacy Violation", "Medium", "/search.aspx", ""},
			{"Privacy Violation", "Medium", "/subscribe.aspx", ""},
			{"Privacy Violation", "Medium", "/survey_questions.aspx", ""},
			{"Information Exposure Through Environmental Variables", "Low", "/aaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbthbbbbbbbbbbbbb.bbbbbbb", ""},
		};
	
	public final static String[][] ntoSix = new String [][] {
		{"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/Login.asp", "tfUPass"},
		{"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/Register.asp", "tfRName"},
		{"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/showforum.asp", "id"},
		{"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/showthread.asp", "id"},
		{"Improper Restriction of Excessive Authentication Attempts", "Critical", "/Login.asp", "tfUPass"},
		{"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "High", "/Search.asp", "tfSearch"},
		{"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "High", "/Templatize.asp", "item"},
		{"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "High", "/showforum.asp", "id"},
		{"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "High", "/showthread.asp", "id"},
		{"Integer Overflow or Wraparound", "High", "/showforum.asp", "id"},
		{"Integer Overflow or Wraparound", "High", "/showthread.asp", "id"},
		{"Unprotected Transport of Credentials", "High", "/Login.asp", "N/A"},
		{"Unprotected Transport of Credentials", "High", "/Register.asp", "N/A"},
		{"Exposure of Backup File to an Unauthorized Control Sphere", "Medium", "/robots.txt", "N/A"},
		{"Information Exposure", "Medium", "/Templatize.asp", "N/A"},
		{"Information Exposure", "Medium", "/showforum.asp", "N/A"},
		{"Information Exposure Through Browser Caching", "Medium", "/Login.asp", "N/A"},
		{"Information Exposure Through Browser Caching", "Medium", "/Register.asp", "N/A"},
		{"Information Exposure Through Caching", "Medium", "/Login.asp", "N/A"},
		{"URL Redirection to Untrusted Site ('Open Redirect')", "Medium", "/Logout.asp", "RetURL"},
		{"Cleartext Storage of Sensitive Information", "Low", "/", "N/A"},
		{"Cross-Site Request Forgery (CSRF)", "Low", "/Login.asp", "N/A"},
		{"Cross-Site Request Forgery (CSRF)", "Low", "/Register.asp", "N/A"},
		{"Exposure of Backup File to an Unauthorized Control Sphere", "Low", "/login.asp", "N/A"},
		{"Information Exposure", "Low", "/showthread.asp", "N/A"},
	};
	
	public final static String[][] w3afResults = new String[] [] { 
		{EVAL_INJECTION,"High", "/demo/EvalInjection2.php","command"},
		{XSS, "High", "/demo/XSS-cookie.php", "cookie"},
		{LDAP_INJECTION,"High", "/demo/LDAPInjection2.php","username"},
		{OS_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
		{SQLI,"High", "/demo/SQLI2.php","username"},
		{XPATH_INJECTION,"Medium", "/demo/XPathInjection2.php","password"},
		{XPATH_INJECTION,"Medium", "/demo/XPathInjection2.php","username"},
		{XSS,"Medium", "/demo/EvalInjection2.php","command"},
		{XSS,"Medium", "/demo/XSS-reflected2.php","username"},
		{FORMAT_STRING_INJECTION,"Medium", "/demo/FormatString2.php","name"},
		{FORCED_BROWSING,"Info", "/demo.zip",""},
		{FORCED_BROWSING,"Info", "/demo/PredictableResource.php.bak",""},
		
	};
	
	public final static String[][] zapProxyResults = new String [][] {
			{DIRECTORY_LISTING, "High", "/demo/DirectoryIndexing/", ""},
			{XSS, "Medium", "/demo/EvalInjection2.php", "command"},
			{XSS, "Medium", "/demo/XPathInjection2.php", "password"},
			{XSS, "Medium", "/demo/XPathInjection2.php", "username"},
			{XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
			{SQLI, "Medium", "/demo/SQLI2.php", "username"},
		};
	
	public final static String[][] nessusResults = new String [][] {
			{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
			{SQLI, "Critical", "/demo/SQLI2.php", "username"},
			{FORCED_BROWSING, "Medium", "/demo/PredictableResource.php.bak", ""},
			{EXTERNAL_FILEPATH_CONTROL, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
			{XSS, "Medium", "/demo/EvalInjection2.php", "command"},
			{XSS, "Medium", "/demo/XPathInjection2.php", "password"},
			{XSS, "Medium", "/demo/XSS-cookie.php", "cookie"},
			{XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
			{SESSION_FIXATION, "Medium", "/demo/XSS-reflected2.php", "username"},
			{DIRECTORY_LISTING, "Low", "/demo/DirectoryIndexing/", ""},
		};
	
	public final static String[][] arachniResults = new String [][] {
			{XSS, "Critical", "/demo/EvalInjection2.php", "command"},
			{XSS, "Critical", "/demo/XPathInjection2.php", "password"},
			{XSS, "Critical", "/demo/XPathInjection2.php", "username"},
			{XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
			{LDAP_INJECTION, "Critical", "/demo/LDAPInjection2.php", "username"},
			{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
			{SQLI, "Critical", "/demo/SQLI2.php", "username"},
			{XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "password"},
			{XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "username"},
			{INFO_LEAK_DIRECTORIES, "High", "/demo/", ""},
		};
	
	public final static String[][] webInspectResults = new String [][] {
			{XSS, "Critical", "/demo/EvalInjection2.php", "command"},
			{XSS, "Critical", "/demo/XSS-cookie.php", "cookie"},
			{XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
			{OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
			{INFORMATION_EXPOSURE, "Critical", "/demo/SQLI2.php", "username"},
			{INFORMATION_EXPOSURE, "Critical", "/demo/password.txt", ""},
			{INFORMATION_EXPOSURE, "High", "/demo/OSCommandInjection2.php", "fileName"},
			{INFORMATION_EXPOSURE, "High", "/demo/PredictableResource.php.BAK", ""},
			{INFORMATION_EXPOSURE, "High", "/demo/PredictableResource.php.bak", ""},
			{FORCED_BROWSING, "Medium", "/test.php", ""},
			{ACCESS_CONTROL, "Medium", "/demo/XPathInjection2.php", ""},
			{LDAP_INJECTION, "Medium", "/demo/LDAPInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Medium", "/demo/LDAPInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/cgi-bin/test.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/EvalInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/FormatString2.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/OSCommandInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/PathTraversal.php", "action"},
			{INFORMATION_EXPOSURE, "Low", "/demo/SQLI2.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/XPathInjection2.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/demo/XSS-cookie.php", "cookie"},
			{INFORMATION_EXPOSURE, "Low", "/demo/XSS-reflected2.php", ""},
			{INFORMATION_EXPOSURE, "Low", "/test.php", ""},
			{DIRECTORY_LISTING, "Low", "/cgi-bin/", ""},
			{DIRECTORY_LISTING, "Low", "/demo/", ""},
			{INFORMATION_EXPOSURE, "Info", "/", ""},
	};
	
	public final static String[][] brakemanResults = new String [][] {
			{XSS, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/views/users/index.html", "User.new"},
			{XSS, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/views/users/results.html", "null"},
			{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
			{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
			{OS_INJECTION, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
			
			
			{SQLI, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:query]"},
			{OPEN_REDIRECT, "Critical", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params"},
			{CSRF, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/application_controller.rb", "null"},
			
			
			{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "params[:post]"},
			{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "params[:post]"},
			{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user]"},
			
			{EXTERNAL_CONTROL_OF_PARAM, "High", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user]"},
			
			
			{ARGUMENT_INJECTION, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/models/user.rb", "null"},
			
			{ARGUMENT_INJECTION, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/models/user.rb", "null"},
			
			{FORCED_BROWSING, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/config/routes.rb", "null"},
			{EXTERNAL_CONTROL_OF_PARAM, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/post, user.rb", "null"},
			
			{OPEN_REDIRECT, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "Post.find(params[:id])"},
			{OPEN_REDIRECT, "Medium", "/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "User.find(params[:id])"},
		};
	
	public final static String[][] fortify360Results = new String [][] {
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Address"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "BillingDate"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "BillingDate"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CcfUsed"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CityServices"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CurrentElectricity"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CurrentNaturalGas"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CustomerNumber"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CustomerNumber"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "KiloWattHourUsed"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Name"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Payments"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "PreviousBill"},
			{XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "StateLocalTaxes"},
			{XSS, "High", "/ZigguratUtilityWeb/ContactUs.aspx", "email"},
			{XSS, "High", "/ZigguratUtilityWeb/ContactUs.aspx", "txtSubject"},
			{XSS, "High", "/ZigguratUtilityWeb/MakePayment.aspx", "txtCardNumber"},
			{XSS, "High", "/zigguratutilityweb/message.aspx", "Msg"},
			{SQLI, "High", "/ZigguratUtilityWeb/LoginPage.aspx", "txtUsername"},
			{SQLI, "High", "/ZigguratUtilityWeb/ViewStatement.aspx", "StatementID"},
			{ASP_NET_DEBUG, "Medium", "/ZigguratUtilityWeb/web.config", ""},
			{ASP_NET_CUSTOM_ERROR, "Medium", "/ZigguratUtilityWeb/web.config", ""},
			{ASP_NET_VALIDATION_MISSING, "Medium", "/zigguratutilityweb/message.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/ViewStatement.aspx", ""},
			{IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/ViewStatement.aspx", ""},
			{NON_SERIALIZABLE_OBJECT, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
			{TRUST_BOUNDARY_VIOLATION, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
			{NULL_POINTER, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
			{NULL_POINTER, "Medium", "/ZigguratUtilityWeb/MakePayment.aspx", ""},
			{NULL_POINTER, "Medium", "/ZigguratUtilityWeb/MakePayment.aspx", ""},
			{SQLI, "Info", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", ""},
			{UNCHECKED_ERROR, "Info", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", ""}
		};
	
	public final static String[][] acunetixResults = new String [][] {
			{XSS, "Critical", "/comments.aspx", "tbComment"},
			{XSS, "Critical", "/readnews.aspx", "NewsAd"},
			{SQLI, "Critical", "/comments.aspx", "id"},
			{SQLI, "Critical", "/comments.aspx", "tbComment"},
			{SQLI, "Critical", "/login.aspx", "tbUsername"},
			{SQLI, "Critical", "/readnews.aspx", "id"},
			{CLEARTEXT_SENSITIVE_INFO, "Medium", "/login.aspx", ""},
			{CLEARTEXT_SENSITIVE_INFO, "Medium", "/signup.aspx", ""},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/default.aspx", "delete"},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/readnews.aspx", "id"},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "/readnews.aspx", "NewsAd"},
			{INFO_EXPOSURE_ERROR_MESSAGE, "Medium", "Web Server", ""},
			{IMPROPER_RESTRICTION_AUTH, "Low", "/login.aspx", ""},
			{IMPROPER_RESTRICTION_AUTH, "Low", "/signup.aspx", ""},
			{INFORMATION_EXPOSURE, "Low", "Web Server", ""},
			{NON_SECURE_COOKIE, "Low", "/", ""},
			{FILES_ACCESSIBLE, "Info", "/_vti_cnf", ""},
			{FILES_ACCESSIBLE, "Info", "/_vti_cnf/acublog.csproj", ""},
			{FILES_ACCESSIBLE, "Info", "/_vti_cnf/acublog.csproj.webinfo", ""},
			{FILES_ACCESSIBLE, "Info", "/login.aspx", ""},
			{FILES_ACCESSIBLE, "Info", "/login.aspx.cs", ""},
			{FILES_ACCESSIBLE, "Info", "/login.aspx.resx", ""},
			{FILES_ACCESSIBLE, "Info", "/web.config", ""},
			{INFO_LEAK_BROWSER_CACHE, "Info", "/login.aspx", ""},
			{INFO_LEAK_BROWSER_CACHE, "Info", "/signup.aspx", ""},
		};
	
	public final static String[][] burpResults = new String [][] {
			{XSS, "High", "/demo/EvalInjection2.php", "command"},
			{XSS, "High", "/demo/XSS-reflected2.php", "username"},
			{OS_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
			{SQLI, "High", "/demo/SQLI2.php", "username"},
			{IMPROPER_CROSS_BOUNDARY_REMOVAL_OF_DATA, "Info", "/demo/PredictableResource.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/DirectoryIndexing/admin.txt", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/EvalInjection.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/EvalInjection2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/FormatString.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/FormatString2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/LDAPInjection.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/LDAPInjection2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/OSCommandInjection.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/OSCommandInjection2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/PathTraversal.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/PredictableResource.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/SQLI.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/SQLI2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XPathInjection.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XPathInjection2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-cookie.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-reflected.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-reflected2.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-stored.php", ""},
			{FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS.php", ""},
			{INFORMATION_EXPOSURE, "Info", "/",""},
			{DIRECTORY_LISTING,"Info","/demo/DirectoryIndexing/",""},
		};
	
	public final static Map<String, String[][]> SCAN_RESULT_MAP = new HashMap<>();
	static {
		SCAN_RESULT_MAP.put("Microsoft CAT.NET", catnetResults);
		SCAN_RESULT_MAP.put("FindBugs", findBugsResults);
		SCAN_RESULT_MAP.put("IBM Rational AppScan", ibmAppScanResults);
		SCAN_RESULT_MAP.put("Mavituna Security Netsparker",netsparkerResults );
		SCAN_RESULT_MAP.put("Skipfish", skipfishResults);
		SCAN_RESULT_MAP.put("w3af", w3afResults);
		SCAN_RESULT_MAP.put("OWASP Zed Attack Proxy",zapProxyResults);
		SCAN_RESULT_MAP.put("Nessus", nessusResults);
		SCAN_RESULT_MAP.put("Arachni", arachniResults);
		SCAN_RESULT_MAP.put("WebInspect",webInspectResults);
		SCAN_RESULT_MAP.put("NTO Spider",ntospiderResults);
		SCAN_RESULT_MAP.put("NTO Spider6",ntoSix);
		SCAN_RESULT_MAP.put("Brakeman", brakemanResults); 
		SCAN_RESULT_MAP.put("Fortify 360", fortify360Results);
		SCAN_RESULT_MAP.put("Acunetix WVS", acunetixResults);
		SCAN_RESULT_MAP.put("Burp Suite", burpResults );
		SCAN_RESULT_MAP.put("IBM Rational AppScan Source Edition", null);
	}
	
	public static String getScanFilePath(String category, String scannerName, String fileName) {
		String string = "SupportingFiles/" + category  + "/" + scannerName + "/" + fileName;
		
		String urlFromCommandLine = System.getProperty("scanFileBaseLocation");
		if (urlFromCommandLine != null) {
			return urlFromCommandLine + string;
		}
		
		return ScanTests.class.getClassLoader().getResource(string).toString();
	}
	

	
}
