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
public class CenzicScanTest extends TransactionalTest {

    public final static String[][] cenzicResults = new String [][] {
            {XSS, "High", "/Kelev/php/accttransaction.php", "FromDate"},
            {XSS, "High", "/Kelev/php/accttransaction.php", "ToDate"},
            {XSS, "High", "/Kelev/php/loanrequestdetail.php", "hUserId"},
            {XSS, "High", "/Kelev/php/login.php", "hUserType"},
            {XSS, "High", "/Kelev/register/register.php", "UserId"},
            {XSS, "High", "/Kelev/view/updateloanrequest.php", "txtAnnualIncome"},
            {XSS, "High", "/Kelev/view/updateloanrequest.php", "txtFirstName"},
            {XSS, "High", "/tracker/rest/gadget/1.0/project/generate", "projectsOrCategories"},
    };

    @Test
     public void cenzicScanTest() {
        ScanComparisonUtils.compare(cenzicResults, ScanLocationManager.getRoot() +
                "Dynamic/CenzicHailstorm/ReportItem_2013-06-21_09-14.xml");
    }
}
