////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;

public class ScanAgentTasksPage extends BasePage{

    public ScanAgentTasksPage(WebDriver webdriver) {
        super(webdriver);
    }

    public int getScanAgentTaskId(String date) {
        int rowCnt = driver.findElementsByClassName("bodyRow").size();
        for (int i = 0; i < rowCnt; i++) {
            try {
                if (driver.findElementById("createTime" + i).getText().trim().equals(date)) {
                    return i;
                }
            } catch (NoSuchElementException e) {
                System.err.println("Scan Agent Task with date of: " + date + " could not be found. " + e.getMessage());
                return -1;
            }
        }
        return -1;
    }

    public ScanAgentTasksPage clickDeleteScan(int scanId) {
        driver.findElementById("deleteButton" + scanId).click();
        handleAlert();
        return new ScanAgentTasksPage(driver);
    }

    public String successAlert() {
        return driver.findElementByClassName("alert-success").getText().trim();
    }

    /*________________ Boolean Functions ________________*/
    public boolean isScanAgentTaskPresent(String date) {
        int rowCnt = driver.findElementsByClassName("bodyRow").size();
        for (int i = 0; i < rowCnt; i++) {
            try {
                if (driver.findElementById("scanAgentTaskCreateTime" + i).getText().trim().equals(date)) {
                    return true;
                }
            } catch (NoSuchElementException e) {
                System.err.println("Scan Agent Task with date of: " + date + " could not be found. " + e.getMessage());
                return false;
            }
        }
        return false;
    }
}
