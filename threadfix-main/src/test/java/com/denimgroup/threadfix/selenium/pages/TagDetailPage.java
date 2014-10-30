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

public class TagDetailPage extends BasePage{

    public TagDetailPage(WebDriver webDriver) {
        super(webDriver);
    }

    /*------------------------------ Action Methods ------------------------------*/

    public ApplicationDetailPage clickAppName(String appName) {
        driver.findElementByLinkText(appName).click();
        waitForElement(driver.findElementById("nameText"));
        return new ApplicationDetailPage(driver);
    }

    public TeamDetailPage clickTeamName(String teamName) {
        driver.findElementByLinkText(teamName).click();
        waitForElement(driver.findElementById("name"));
        return new TeamDetailPage(driver);
    }

    /*------------------------------ Get Methods ------------------------------*/

    public String getNumberofAttachedApps() {
        return driver.findElementById("numApps").getText().trim();
    }

    public String getNumberofAttachedComments() {
        return driver.findElementById("numVulnComments").getText().trim();
    }

    /*------------------------------ Boolean Methods ------------------------------*/

    public boolean isTagAttachedtoApp(String appName) { return !driver.findElementsByLinkText(appName).isEmpty(); }
}
