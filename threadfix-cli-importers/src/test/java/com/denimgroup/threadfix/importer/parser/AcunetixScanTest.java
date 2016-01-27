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
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class AcunetixScanTest extends TransactionalTest {

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

    @Test
     public void acunetixScanTest() {
        ScanComparisonUtils.compare(acunetixResults, ScanLocationManager.getRoot() +
                "Dynamic/Acunetix/testaspnet.xml");
    }
}
