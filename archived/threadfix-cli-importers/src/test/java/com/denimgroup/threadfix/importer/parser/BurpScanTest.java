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
/**
 * Created by denimgroup on 2/10/14.
 */
public class BurpScanTest extends TransactionalTest {

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

    @Test
    public void burpScanTest() {
        ScanComparisonUtils.compare(burpResults, ScanLocationManager.getRoot() +
                "Dynamic/Burp/burp-demo-site.xml");
    }

    public final static String[][] sbirResults = new String [][] {
            {XSS, "High", "/Test/WebForm1.aspx", "newitem"},
    };

    @Test
    public void burpScanTest2() {
        ScanComparisonUtils.compare(sbirResults, ScanLocationManager.getRoot() +
                "SBIR/webform.xml");
    }
}
