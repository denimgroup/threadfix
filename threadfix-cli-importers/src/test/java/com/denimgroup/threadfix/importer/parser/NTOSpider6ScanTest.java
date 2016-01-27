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

package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
/**
 * Created by denimgroup on 2/10/14.
 */
public class NTOSpider6ScanTest extends TransactionalTest {

    public final static String[][] ntoSix = new String [][] {
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/Login.asp", "tfUPass"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/Register.asp", "tfRName"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/showforum.asp", "id"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/showthread.asp", "id"},
            {"Improper Restriction of Excessive Authentication Attempts", "High", "/Login.asp", "tfUPass"},
            {"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Medium", "/Search.asp", "tfSearch"},
            {"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "Medium", "/Templatize.asp", "item"},
            {"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "Medium", "/showforum.asp", "id"},
            {"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "Medium", "/showthread.asp", "id"},
            {"Integer Overflow or Wraparound", "Medium", "/showforum.asp", "id"},
            {"Integer Overflow or Wraparound", "Medium", "/showthread.asp", "id"},
            {"Unprotected Transport of Credentials", "Medium", "/Login.asp", "N/A"},
            {"Unprotected Transport of Credentials", "Medium", "/Register.asp", "N/A"},
            {"Exposure of Backup File to an Unauthorized Control Sphere", "Low", "/robots.txt", "N/A"},
            {"Information Exposure", "Low", "/Templatize.asp", "N/A"},
            {"Information Exposure", "Low", "/showforum.asp", "N/A"},
            {"Information Exposure Through Browser Caching", "Low", "/Login.asp", "N/A"},
            {"Information Exposure Through Browser Caching", "Low", "/Register.asp", "N/A"},
            {"Information Exposure Through Caching", "Low", "/Login.asp", "N/A"},
            {"URL Redirection to Untrusted Site ('Open Redirect')", "Low", "/Logout.asp", "RetURL"},
            {"Cleartext Storage of Sensitive Information", "Info", "/", "N/A"},
            {"Cross-Site Request Forgery (CSRF)", "Info", "/Login.asp", "N/A"},
            {"Cross-Site Request Forgery (CSRF)", "Info", "/Register.asp", "N/A"},
            {"Exposure of Backup File to an Unauthorized Control Sphere", "Info", "/login.asp", "N/A"},
            {"Information Exposure", "Info", "/showthread.asp", "N/A"},
    };

    @Test
    public void ntoSpiderSixScan() {
        ScanComparisonUtils.compare(ntoSix, ScanLocationManager.getRoot() +
                "Dynamic/NTOSpider/VulnerabilitiesSummary6.xml");
    }
}
