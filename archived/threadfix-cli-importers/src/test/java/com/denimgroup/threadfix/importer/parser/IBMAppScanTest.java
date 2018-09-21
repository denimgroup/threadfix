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
public class IBMAppScanTest extends TransactionalTest {

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

    @Test
    public void ibmScanTest() {
        ScanComparisonUtils.compare(ibmAppScanResults, ScanLocationManager.getRoot() +
                "Dynamic/AppScan/appscan-php-demo.xml");
    }
}



