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

package com.denimgroup.threadfix.importer;

import com.denimgroup.threadfix.data.entities.GenericVulnerability;

/**
 * Created by mac on 2/6/14.
 */
public class TestConstants {
    // TODO move to a less fragile method of checking names
    public final static String ACCESS_CONTROL = "Improper Access Control";
    public final static String ARGUMENT_INJECTION = "Argument Injection or Modification";
    public final static String ASP_NET_CUSTOM_ERROR = "ASP.NET Misconfiguration: Missing Custom Error Page";
    public final static String ASP_NET_DEBUG = "ASP.NET Misconfiguration: Creating Debug Binary";
    public final static String ASP_NET_VALIDATION_MISSING = "ASP.NET Misconfiguration: Not Using Input Validation Framework";
    public final static String CLEARTEXT_SENSITIVE_INFO = "Cleartext Transmission of Sensitive Information";
    public final static String CODE_INJECTION = "Improper Control of Generation of Code ('Code Injection')";
    public final static String COMMAND_INJECTION = "Improper Neutralization of Special Elements used in a Command ('Command Injection')";
    public final static String CONFIGURATION = "Configuration";
    public final static String CSRF = "Cross-Site Request Forgery (CSRF)";
    public final static String DIRECTORY_LISTING = "Information Exposure Through Directory Listing";
    public final static String EVAL_INJECTION = GenericVulnerability.CWE_EVAL_INJECTION;
    public final static String EXTERNAL_CONTROL_OF_PARAM = "External Control of Assumed-Immutable Web Parameter";
    public final static String EXTERNAL_FILEPATH_CONTROL = "External Control of File Name or Path";
    public final static String FAILURE_TO_HANDLE_ENCODING = "Improper Handling of Alternate Encoding";
    public final static String FILES_ACCESSIBLE = "Files or Directories Accessible to External Parties";
    public final static String FORCED_BROWSING = "Direct Request ('Forced Browsing')";
    public final static String FORMAT_STRING_INJECTION = GenericVulnerability.CWE_FORMAT_STRING_INJECTION;
    public final static String GENERIC_INJECTION = "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')";
    public final static String IMPROPER_CROSS_BOUNDARY_REMOVAL_OF_DATA = "Improper Cross-boundary Removal of Sensitive Data";
    public final static String IMPROPER_HANDLING_OF_MISSING_VALUES = "Improper Handling of Missing Values";
    public final static String IMPROPER_INPUT_VALIDATION = "Improper Input Validation";
    public final static String IMPROPER_RESOURCE_SHUTDOWN = "Improper Resource Shutdown or Release";
    public final static String IMPROPER_RESTRICTION_AUTH = "Improper Restriction of Excessive Authentication Attempts";
    public final static String INFORMATION_EXPOSURE = "Information Exposure";
    public final static String INFO_EXPOSURE_ERROR_MESSAGE = "Information Exposure Through an Error Message";
    public final static String INFO_LEAK_BROWSER_CACHE = "Information Exposure Through Browser Caching";
    public final static String INFO_LEAK_COMMENTS = "Information Exposure Through Comments";
    public final static String INFO_LEAK_DIRECTORIES = "File and Directory Information Exposure";
    public final static String INFO_LEAK_SERVER_ERROR = "Information Exposure Through Server Error Message";
    public final static String INFO_LEAK_TEST_CODE = "Information Exposure Through Test Code";
    public final static String LDAP_INJECTION = GenericVulnerability.CWE_LDAP_INJECTION;
    public final static String NON_SECURE_COOKIE = "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute";
    public final static String NON_SERIALIZABLE_OBJECT = "J2EE Bad Practices: Non-serializable Object Stored in Session";
    public final static String NULL_POINTER = "Unchecked Return Value to NULL Pointer Dereference";
    public final static String OPEN_REDIRECT = "URL Redirection to Untrusted Site ('Open Redirect')";
    public final static String OS_INJECTION = GenericVulnerability.CWE_OS_COMMAND_INJECTION;
    public final static String PATH_TRAVERSAL = GenericVulnerability.CWE_PATH_TRAVERSAL;
    public final static String REFLECTION_ATTACK = "Reflection Attack in an Authentication Protocol";
    public final static String RESOURCE_INJECTION = "Improper Control of Resource Identifiers ('Resource Injection')";
    public final static String SESSION_FIXATION = "Session Fixation";
    public final static String SOURCE_CODE_INCLUDE = "Information Exposure Through Include Source Code";
    public final static String SQLI = GenericVulnerability.CWE_SQL_INJECTION;
    public final static String TRUST_BOUNDARY_VIOLATION = "Trust Boundary Violation";
    public final static String UNCHECKED_ERROR = "Unchecked Error Condition";
    public final static String XML_INJECTION = "XML Injection (aka Blind XPath Injection)";
    public final static String XPATH_INJECTION = GenericVulnerability.CWE_XPATH_INJECTION;
    public final static String XSS = GenericVulnerability.CWE_CROSS_SITE_SCRIPTING;
}
