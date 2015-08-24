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
package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class FindingDetailPage extends BasePage {

    public FindingDetailPage(WebDriver webDriver) {
        super(webDriver);
    }

    public VulnerabilityDetailPage clickViewVulnerability() {
        driver.findElementByLinkText("View Vulnerability").click();
        sleep(3000);
        waitForElement(By.id("uploadDocVulnModalLink"));
        return new VulnerabilityDetailPage(driver);
    }

    public VulnerabilityDetailPage clickViewVulnerabilityLimitedPermission() {
        driver.findElementByLinkText("View Vulnerability").click();
        sleep(3000);
        waitForElement(By.id("cweLink"));
        return new VulnerabilityDetailPage(driver);
    }

    public MergeFindingPage clickMergeWithOtherFindings() {
        driver.findElementByLinkText("Merge with Other Findings").click();
        sleep(3000);
        waitForElement(By.className("dataTable"));
        return new MergeFindingPage(driver);
    }
    public String getDetail(String detailId) {
        return driver.findElementById(detailId).getText().trim();
    }

    public boolean isViewVulnetabilityButtonDisplayed() {
        return driver.findElementByLinkText("View Vulnerability").isDisplayed();
    }

    public boolean isScannerVulnerabilityTextPresent() {
        return driver.findElementById("scannerVulnerabilityType").isDisplayed();
    }

}
