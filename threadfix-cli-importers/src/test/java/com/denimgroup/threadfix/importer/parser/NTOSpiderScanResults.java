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

package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
/**
 * Created by denimgroup on 2/10/14.
 */
public class NTOSpiderScanResults extends TransactionalTest {

    public final static String[][] ntospiderResults = new String [][] {
            {"Improper Authentication", "High", "/bank/login.aspx", "N/A"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/bank/login.aspx", "passw"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/bank/login.aspx", "uid"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "High", "/subscribe.aspx", "txtEmail"},
            {"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "Medium", "/bank/login.aspx", "uid"},
            {"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "Medium", "/comment.aspx", "name"},
            {"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "Medium", "/notfound.aspx", "aspxerrorpath"},
            {"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "Medium", "/search.aspx", "txtSearch"},
            {"Information Exposure Through Directory Listing", "Low", "/bank/", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/bank/login.aspx", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/comment.aspx", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/default.aspx", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/disclaimer.htm", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/feedback.aspx", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/notfound.aspx", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/search.aspx", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/subscribe.aspx", "N/A"},
            {"Exposure of Private Information ('Privacy Violation')", "Low", "/survey_questions.aspx", "N/A"},
            {"Information Exposure Through Environmental Variables", "Info", "/aaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbthbbbbbbbbbbbbb.bbbbbbb", "N/A"},
    };

    @Test
    public void ntoSpiderScanTest() {
        ScanComparisonUtils.compare(ntospiderResults, ScanLocationManager.getRoot() +
                "Dynamic/NTOSpider/VulnerabilitiesSummary.xml");
    }
}
