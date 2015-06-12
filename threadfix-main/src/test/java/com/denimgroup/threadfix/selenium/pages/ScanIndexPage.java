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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class ScanIndexPage extends BasePage {

    private WebElement scanTable;

    public ScanIndexPage(WebDriver webdriver) {
        super(webdriver);
        scanTable = driver.findElementById("main-content");
    }

    public int getNumScanRows() {
        int cnt = driver.findElementsByClassName("bodyRow").size();
        if (cnt == 1) {
            if (driver.findElementByClassName("bodyRow").getText().contains("No scans found.")) {
                return 0;
            }
        }
        return cnt;
    }

    public ScanDetailPage clickViewScanLink(String teamName, String appName, String scanner) {
        if (getNumScanRows() == 0) {
            return null;
        }
        //TODO: Update once this page has ids added
        driver.findElementByXPath("//tr[td/text() = \'" + appName + "\' and td/text() = \'" + teamName +
            "\' and td/text() = '" + scanner + "\']//a").click();
        return new ScanDetailPage(driver);
    }
}