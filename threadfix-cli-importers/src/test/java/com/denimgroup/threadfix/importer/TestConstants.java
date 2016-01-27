////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.importer;

import com.denimgroup.threadfix.data.entities.GenericVulnerability;

/**
 * Created by mac on 2/6/14.
 */
public interface TestConstants {

    public final static String
            ACCESS_CONTROL = "Improper Access Control",
            ARGUMENT_INJECTION = "Argument Injection or Modification",
            ASP_NET_CUSTOM_ERROR = "ASP.NET Misconfiguration: Missing Custom Error Page",
            ASP_NET_DEBUG = "ASP.NET Misconfiguration: Creating Debug Binary",
            ASP_NET_VALIDATION_MISSING = "ASP.NET Misconfiguration: Not Using Input Validation Framework",
            CLEARTEXT_SENSITIVE_INFO = "Cleartext Transmission of Sensitive Information",
            CODE_INJECTION = "Improper Control of Generation of Code ('Code Injection')",
            COMMAND_INJECTION = "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
            CONFIGURATION = "Configuration",
            CSRF = "Cross-Site Request Forgery (CSRF)",
            DIRECTORY_LISTING = "Information Exposure Through Directory Listing",
            EVAL_INJECTION = GenericVulnerability.CWE_EVAL_INJECTION,
            EXTERNAL_CONTROL_OF_PARAM = "External Control of Assumed-Immutable Web Parameter",
            EXTERNAL_FILEPATH_CONTROL = "External Control of File Name or Path",
            FAILURE_TO_HANDLE_ENCODING = "Improper Handling of Alternate Encoding",
            FILES_ACCESSIBLE = "Files or Directories Accessible to External Parties",
            FORCED_BROWSING = "Direct Request ('Forced Browsing')",
            FORMAT_STRING_INJECTION = GenericVulnerability.CWE_FORMAT_STRING_INJECTION,
            GENERIC_INJECTION = "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
            IMPROPER_AUTHENTICATION = "Improper Authentication",
            IMPROPER_CROSS_BOUNDARY_REMOVAL_OF_DATA = "Improper Cross-boundary Removal of Sensitive Data",
            IMPROPER_HANDLING_OF_MISSING_VALUES = "Improper Handling of Missing Values",
            IMPROPER_INPUT_VALIDATION = "Improper Input Validation",
            IMPROPER_RESOURCE_SHUTDOWN = "Improper Resource Shutdown or Release",
            IMPROPER_RESTRICTION_AUTH = "Improper Restriction of Excessive Authentication Attempts",
            INFORMATION_EXPOSURE = "Information Exposure",
            INFO_EXPOSURE_ERROR_MESSAGE = "Information Exposure Through an Error Message",
            INFO_LEAK_BROWSER_CACHE = "Information Exposure Through Browser Caching",
            INFO_LEAK_COMMENTS = "Information Exposure Through Comments",
            INFO_LEAK_DIRECTORIES = "File and Directory Information Exposure",
            INFO_LEAK_SERVER_ERROR = "Information Exposure Through Server Error Message",
            INFO_LEAK_TEST_CODE = "Information Exposure Through Test Code",
            LDAP_INJECTION = GenericVulnerability.CWE_LDAP_INJECTION,
            NON_SECURE_COOKIE = "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
            NON_SERIALIZABLE_OBJECT = "J2EE Bad Practices: Non-serializable Object Stored in Session",
            NULL_POINTER = "Unchecked Return Value to NULL Pointer Dereference",
            OPEN_REDIRECT = "URL Redirection to Untrusted Site ('Open Redirect')",
            OS_INJECTION = GenericVulnerability.CWE_OS_COMMAND_INJECTION,
            PATH_TRAVERSAL = GenericVulnerability.CWE_PATH_TRAVERSAL,
            REFLECTION_ATTACK = "Reflection Attack in an Authentication Protocol",
            RESOURCE_INJECTION = "Improper Control of Resource Identifiers ('Resource Injection')",
            SESSION_FIXATION = "Session Fixation",
            SOURCE_CODE_INCLUDE = "Information Exposure Through Include Source Code",
            SQLI = GenericVulnerability.CWE_SQL_INJECTION,
            TRUST_BOUNDARY_VIOLATION = "Trust Boundary Violation",
            UNCHECKED_ERROR = "Unchecked Error Condition",
            XML_INJECTION = "XML Injection (aka Blind XPath Injection)",
            XPATH_INJECTION = GenericVulnerability.CWE_XPATH_INJECTION,
            XSS = GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
            BURP_CONFIDENCE_FIRM = "Firm",
            BURP_CONFIDENCE_CERTAIN = "Certain",
            BURP_CONFIDENCE_TENATIVE = "Tentative";
}
