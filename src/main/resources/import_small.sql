-- ----------------------------------------------------------------------
-- Small Report of Data
--  USAGE: Use for importing for smaller testing.
--	Date: January 18th 2011
--
-- 	Runtime: Command Line mysql source [file] (0.5 - 1.5 minutes)
-- 	Contains Mappings for: 	Cat.NET, AppScan
--
--							Generic Mappings to CWEs
--							Vulnerability and Severity Maps to Generics
--							Sample Organizations and Applications
--							WafTypes
--							DefectTrackerTypes
--							Survey (OpenSAMM)
--
-- 		  Needs data for: Fortify, Orizon, AppScanSE
--
-- 	NOTES: 	A small version of import.sql containing only data for
--			AppScan and Cat.NET
--
--  ERRORS: DO NOT run after running import.sql - Inserts will cause duplication
-- ----------------------------------------------------------------------


-- ------------------------------------
-- ROLES -------------------
-- ------------------------------------
INSERT INTO Role (id, displayName, name) VALUES (1, 'Administrator', 'ROLE_ADMIN');
INSERT INTO Role (id, displayName, name) VALUES (2, 'User', 'ROLE_USER');

-- ------------------------------------
-- SAMPLE ORGS/APPS -------------------
-- ------------------------------------
insert into organization (name, createdDate, modifiedDate, active) values ('SRS', now(), now(), 1);
insert into organization (name, createdDate, modifiedDate, active) values ('Procurement', now(), now(), 1);
insert into organization (name, createdDate, modifiedDate, active) values ('Denim Group', now(), now(), 1);

insert into application (name, url, organizationId, createdDate, modifiedDate, active) values ('Order Review', 'http://srs/OrderReview', 1, now(), now(), 1);
insert into application (name, url, organizationId, createdDate, modifiedDate, active) values ('Store Walk', 'http://srs/handheld/storewalk', 1, now(), now(), 1);
insert into application (name, url, organizationId, createdDate, modifiedDate, active) values ('Central Inventory', 'http://srs/ci', 1, now(), now(), 1);
insert into application (name, url, organizationId, createdDate, modifiedDate, active) values ('CMIS', 'http://cmis/index.htm', 2, now(), now(), 1);
insert into application (name, url, organizationId, createdDate, modifiedDate, active) values ('DCC', 'http://intranet.heb.com/dcc', 2, now(), now(), 1);

-- ------------------------------------
-- INSERT CHANNELS --------------------
-- ------------------------------------
INSERT INTO ChannelType (name, url, version) VALUES ('Microsoft CAT.NET', 'http://msdn.microsoft.com/en-us/security/default.aspx', '1 CTP');
INSERT INTO ChannelType (name, url, version) VALUES ('IBM Rational AppScan', 'http://www-01.ibm.com/software/awdtools/appscan/', '-');

SET @cat_net_channel_id := (SELECT id FROM ChannelType WHERE name = 'Microsoft CAT.NET');
SET @appscan_channel_id := (SELECT id FROM ChannelType WHERE name = 'IBM Rational AppScan');


-- ------------------------------------
-- INSERT WAFTYPES --------------------
-- ------------------------------------
INSERT INTO WafType (Name) VALUES ('Snort');
INSERT INTO WafType (Name) VALUES ('mod_security');
INSERT INTO WafType (Name) VALUES ('ESAPI WAF');

SET @snort_waf_type_id := (SELECT id FROM WafType WHERE Name = 'Snort');
SET @mod_security_waf_type_id := (SELECT id FROM WafType WHERE Name = 'mod_security');
SET @esapi_waf_waf_type_id := (SELECT id FROM WafType WHERE Name = 'ESAPI WAF');


-- ------------------------------------
-- INSERT DEFECTTRACKERTYPES ----------
-- ------------------------------------
INSERT INTO DefectTrackerType (Name) VALUES ('Bugzilla');
INSERT INTO DefectTrackerType (Name) VALUES ('Jira');

SET @jira_defect_tracker_id := (SELECT id FROM DefectTrackerType WHERE Name = 'Jira');
SET @bugzilla_defect_tracker_id := (SELECT id FROM DefectTrackerType WHERE Name = 'Bugzilla');


-- ------------------------------------
-- INSERT GENERIC MAPPINGS ------------
-- FOR CATNET & APPSCAN ---------------
-- ------------------------------------
INSERT INTO GenericVulnerability (Name, ID) VALUES ('ASP.NET Environment Issues', '10');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Input Validation', '20');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Special Elements used in a Command (''Command Injection'')', '77');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Preserve Web Page Structure (''Cross-site Scripting'')', '79');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Special Elements used in an SQL Command (''SQL Injection'')', '89');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Data into LDAP Queries (''LDAP Injection'')', '90');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Behavior Order: Validate Before Canonicalize', '180');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Exposure Through an Error Message', '209');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Intended Information Leak', '213');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Restriction of Excessive Authentication Attempts', '307');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Encryption of Sensitive Data', '311');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Cross-Site Request Forgery (CSRF)', '352');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Source Code', '540');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Directory Listing', '548');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('ASP.NET Misconfiguration: Not Using Input Validation Framework', '554');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('URL Redirection to Untrusted Site (''Open Redirect'')', '601');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Session Expiration', '613');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Data within XPath Expressions (''XPath injection'')', '643');

SET @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Special Elements used in an SQL Command (''SQL Injection'')');
SET @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Special Elements used in a Command (''Command Injection'')');
SET @generic_vulnerability_incorrect_behavior_order_validate_before_canonicalize_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Behavior Order: Validate Before Canonicalize');
SET @generic_vulnerability_information_exposure_through_an_error_message_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Exposure Through an Error Message');
SET @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Preserve Web Page Structure (''Cross-site Scripting'')');
SET @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id := (SELECT id FROM GenericVulnerability WHERE Name = 'URL Redirection to Untrusted Site (''Open Redirect'')');
SET @generic_vulnerability_failure_to_sanitize_data_within_xpath_expressions_xpath_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Data within XPath Expressions (''XPath injection'')');
SET @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Data into LDAP Queries (''LDAP Injection'')');
SET @generic_vulnerability_cross_site_request_forgery_csrf_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Cross-Site Request Forgery (CSRF)');
SET @generic_vulnerability_asp_net_environment_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Environment Issues');
SET @generic_vulnerability_information_leak_through_source_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Source Code');
SET @generic_vulnerability_asp_net_misconfiguration_creating_debug_binary_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Misconfiguration: Creating Debug Binary');
SET @generic_vulnerability_information_leak_through_directory_listing_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Directory Listing');
SET @generic_vulnerability_asp_net_misconfiguration_not_using_input_validation_framework_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Misconfiguration: Not Using Input Validation Framework');
SET @generic_vulnerability_missing_encryption_of_sensitive_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Encryption of Sensitive Data');
SET @generic_vulnerability_intended_information_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Intended Information Leak');
SET @generic_vulnerability_insufficient_session_expiration_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Session Expiration');
SET @generic_vulnerability_improper_restriction_of_excessive_authentication_attempts_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Restriction of Excessive Authentication Attempts');
SET @generic_vulnerability_improper_input_validation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Input Validation');


-- ------------------------------------
-- INSERT CHANNEL VULNERABILITIES------
-- ------------------------------------
-- Cat.NET
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL Injection', 'ACESEC01', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Process Command Execution', 'ACESEC02', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('File Canonicalization', 'ACESEC03', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Exception Information', 'ACESEC04', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross-Site Scripting', 'ACESEC05', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Redirection to User Controlled Site', 'ACESEC06', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('XPath Injection', 'ACESEC07', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('LDAP Injection', 'ACESEC08', @cat_net_channel_id);

-- AppScan (VERY INCOMPLETE)
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross-Site Request Forgery', 'Cross-Site Request Forgery', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Application Error', 'Application Error', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross-Site Scripting', 'Cross-Site Scripting', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Microsoft ASP.NET Debugging Enabled', 'Microsoft ASP.NET Debugging Enabled', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Web Application Source Code Disclosure Pattern Found', 'Web Application Source Code Disclosure Pattern Found', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Directory Listing', 'Directory Listing', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Hidden Directory Detected', 'Hidden Directory Detected', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Database Error Pattern Found', 'Database Error Pattern Found', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Unencrypted __VIEWSTATE Parameter', 'Unencrypted __VIEWSTATE Parameter', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL Injection using DECLARE, CAST and EXEC', 'SQL Injection using DECLARE, CAST and EXEC', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL Injection', 'SQL Injection', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Blind SQL Injection', 'Blind SQL Injection', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Unencrypted Login Request', 'Unencrypted Login Request', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Email Address Pattern Found', 'Email Address Pattern Found', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Session Identifier Not Updated', 'Session Identifier Not Updated', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Authentication Bypass Using SQL Injection', 'Authentication Bypass Using SQL Injection', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Inadequate Account Lockout', 'Inadequate Account Lockout', @appscan_channel_id);


-- ------------------------------------
-- INSERT CHANNEL SEVERITY MAPPINGS ---
-- ------------------------------------
-- CAT.NET
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Process Command Execution'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'File Canonicalization'), @generic_vulnerability_incorrect_behavior_order_validate_before_canonicalize_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Exception Information'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Cross-Site Scripting'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Redirection to User Controlled Site'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'XPath Injection'), @generic_vulnerability_failure_to_sanitize_data_within_xpath_expressions_xpath_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'LDAP Injection'), @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id);    
 

-- AppScan (ALSO VERY INCOMPLETE)
-- the mapping for 'Database Error Pattern Found' is too general.
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Cross-Site Request Forgery'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Application Error'), @generic_vulnerability_asp_net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Cross-Site Scripting'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Web Application Source Code Disclosure Pattern Found'), @generic_vulnerability_information_leak_through_source_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Microsoft ASP.NET Debugging Enabled'), @generic_vulnerability_asp_net_misconfiguration_creating_debug_binary_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Directory Listing'), @generic_vulnerability_information_leak_through_directory_listing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Hidden Directory Detected'), @generic_vulnerability_information_leak_through_directory_listing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Unencrypted __VIEWSTATE Parameter'), @generic_vulnerability_asp_net_misconfiguration_not_using_input_validation_framework_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'SQL Injection using DECLARE, CAST and EXEC'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Blind SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Unencrypted Login Request'), @generic_vulnerability_missing_encryption_of_sensitive_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Email Address Pattern Found'), @generic_vulnerability_intended_information_leak_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Session Identifier Not Updated'), @generic_vulnerability_insufficient_session_expiration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Authentication Bypass Using SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Inadequate Account Lockout'), @generic_vulnerability_improper_restriction_of_excessive_authentication_attempts_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Database Error Pattern Found'), @generic_vulnerability_improper_input_validation_id);

    
-- ------------------------------------
-- INSERT CHANNEL SEVERITIES ----------
-- ------------------------------------  
-- INSERT GENERIC MAPPINGS
INSERT INTO GenericSeverity (Name) VALUES ('Critical');
INSERT INTO GenericSeverity (Name) VALUES ('High');
INSERT INTO GenericSeverity (Name) VALUES ('Medium');
INSERT INTO GenericSeverity (Name) VALUES ('Low');
INSERT INTO GenericSeverity (Name) VALUES ('Info');

SET @generic_severity_critical_id := (SELECT id FROM GenericSeverity WHERE Name = 'Critical');
SET @generic_severity_high_id := (SELECT id FROM GenericSeverity WHERE Name = 'High');
SET @generic_severity_medium_id := (SELECT id FROM GenericSeverity WHERE Name = 'Medium');
SET @generic_severity_low_id := (SELECT id FROM GenericSeverity WHERE Name = 'Low');
SET @generic_severity_info_id := (SELECT id FROM GenericSeverity WHERE Name = 'Info');


-- INESRT CHANNEL SEVERITIES
-- CAT.NET
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('High', 'High', @cat_net_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Medium', 'Medium', @cat_net_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Low', 'Low', @cat_net_channel_id);

-- IBM Rational AppScan
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('High', 'High', @appscan_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Medium', 'Medium', @appscan_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Low', 'Low', @appscan_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Informational', 'Informational', @appscan_channel_id);


-- ------------------------------------
-- INSERT CHANNEL SEVERITY MAPPINGS ---
-- ------------------------------------
-- CAT.NET
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'High'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Medium'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Low'), @generic_severity_low_id);

-- IBM Rational AppScan
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscan_channel_id AND Name = 'High'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Medium'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Low'), @generic_severity_low_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Informational'), @generic_severity_info_id);
