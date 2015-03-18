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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.ErrorLogPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertTrue;

//Running test cases in order of method names in ascending order
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category(CommunityTests.class)
public class ErrorLogIT extends BaseDataTest {

    @Test
    public void testCreateSingleError() {
        ErrorLogPage errorLogPage = loginPage.defaultLogin()
                .clickViewLogsLink();

        int initialCount = driver.findElements(By.partialLinkText("Report To ThreadFix Team"))
                .toArray().length;

        if(initialCount < 40) {
            DatabaseUtils.createErrorLog();
            errorLogPage.refreshPage();

            int afterCount = driver.findElements(By.partialLinkText("Report To ThreadFix Team"))
                    .toArray().length;

            assertTrue("A new error was not added.", initialCount + 1 == afterCount);
        }
    }

    @Test
    public void testPagination() {
        for(int i = 1; i <= 51; i++) {
            DatabaseUtils.createErrorLog();
        }
        loginPage.defaultLogin().clickViewLogsLink();

        assertTrue("Pagination did not work", !driver.findElements(By.linkText("2")).isEmpty());
    }
}