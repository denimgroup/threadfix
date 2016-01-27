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
import org.junit.Ignore;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class NessusScanTest extends TransactionalTest {


    public final static String[][] nessusResults = new String [][] {
            {OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
            {SQLI, "Critical", "/demo/SQLI2.php", "username"},
            {FORCED_BROWSING, "Medium", "/demo/PredictableResource.php.bak", ""},
            {EXTERNAL_FILEPATH_CONTROL, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
            {XSS, "Medium", "/demo/EvalInjection2.php", "command"},
            {XSS, "Medium", "/demo/XPathInjection2.php", "password"},
            {XSS, "Medium", "/demo/XSS-cookie.php", "cookie"},
            {XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
            {SESSION_FIXATION, "Medium", "/demo/XSS-reflected2.php", "username"},
            {DIRECTORY_LISTING, "Low", "/demo/DirectoryIndexing/", ""},
    };

    @Ignore // the scan format changed, it automatically parses cwe now. We need to edit this test.
    @Test
    public void nessusScanTest() {
        ScanComparisonUtils.compare(nessusResults, ScanLocationManager.getRoot() +
                "Dynamic/Nessus/nessus_report_TFTarget.xml");
    }
}
