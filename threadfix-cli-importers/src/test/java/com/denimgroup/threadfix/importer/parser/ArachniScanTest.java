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
public class ArachniScanTest extends TransactionalTest {


    public final static String[][] arachniResults = new String [][] {
            {XSS, "Critical", "/demo/EvalInjection2.php", "command"},
            {XSS, "Critical", "/demo/XPathInjection2.php", "password"},
            {XSS, "Critical", "/demo/XPathInjection2.php", "username"},
            {XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
            {LDAP_INJECTION, "Critical", "/demo/LDAPInjection2.php", "username"},
            {OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
            {SQLI, "Critical", "/demo/SQLI2.php", "username"},
            {XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "password"},
            {XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "username"},
            {INFO_LEAK_DIRECTORIES, "High", "/demo/", ""},
    };

    @Test
    public void arachniScanTest() {
        ScanComparisonUtils.compare(arachniResults, ScanLocationManager.getRoot() +
                "Dynamic/Arachni/php-demo.xml");
    }
}
