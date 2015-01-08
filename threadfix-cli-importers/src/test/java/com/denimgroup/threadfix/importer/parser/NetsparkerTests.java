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

import static com.denimgroup.threadfix.importer.TestConstants.*;

// TODO move all the tests to this format.
public class NetsparkerTests extends TransactionalTest {

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

    @Test
    public void netSparkerScanTest() {
        ScanComparisonUtils.compare(netsparkerResults, ScanLocationManager.getRoot() +
                "Dynamic/NetSparker/netsparker-demo-site.xml");
    }

}
