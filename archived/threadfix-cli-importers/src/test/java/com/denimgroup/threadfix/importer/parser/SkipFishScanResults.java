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
public class SkipFishScanResults extends TransactionalTest {

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


    @Test
    public void skipFishScanTest() {
        ScanComparisonUtils.compare(skipfishResults, ScanLocationManager.getRoot() +
                "Dynamic/Skipfish/skipfish-demo-site.zip");
    }
}
