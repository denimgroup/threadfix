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


import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

public class UserPermissionsPage extends BasePage {

	public UserPermissionsPage(WebDriver webdriver) {
		super(webdriver);
	}
	
	public UserPermissionsPage clickAddPermissionsLink(){
		driver.findElementById("addPermissionButton").click();
		waitForElement(driver.findElementById("myModalLabel"));
		sleep(3000);
		return new UserPermissionsPage(driver);
	}
	
	public UserPermissionsPage setTeam(String team){
		new Select(driver.findElement(By.id("orgSelect"))).selectByVisibleText(team);
		return this;
	}

    //Note, the default is that all apps is selected
    public UserPermissionsPage toggleAllApps() {
        driver.findElementById("allAppsCheckbox").click();
        return this;
    }

    public UserPermissionsPage setTeamRole(String role) {
        new Select(driver.findElementById("roleSelectTeam")).selectByVisibleText(role);
        return this;
    }

    public UserPermissionsPage setApplicationRole(String appName, String role) {
        new Select(driver.findElementById("roleSelectApp" + appName)).selectByVisibleText(role);
        return this;
    }

    /*_____________________ Boolean Methods ______________________*/

    public boolean isPermissionPresent(String teamName, String appName, String role) {
        return true;
    }

    public boolean isErrorPresent(String errorMessage) {
        return driver.findElementByClassName("errors").getText().contains(errorMessage);
    }
}
