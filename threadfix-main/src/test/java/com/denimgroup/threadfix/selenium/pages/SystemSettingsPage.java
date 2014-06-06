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
import org.openqa.selenium.support.ui.Select;

public class SystemSettingsPage extends BasePage {

	public SystemSettingsPage(WebDriver webdriver) {
		super(webdriver);
	}
	
	public SystemSettingsPage setRoleSelect(String code){
		new Select(driver.findElementById("roleSelect")).selectByVisibleText(code);
		return this;
	}

	public SystemSettingsPage checkGlobalGroupCheckbox() {
		driver.findElementById("globalGroupEnabledCheckbox").click();
		return this;
	}
	
	public SystemSettingsPage clickUpdateDefaults() {
		driver.findElementById("updateDefaultsButton").click();
		return new SystemSettingsPage(driver);
	}
	
	public boolean isSaveSuccessful(){
		return driver.findElementByClassName("alert-success").getText().trim().contains("Configuration was saved successfully.");
	}

    public SystemSettingsPage defaultPermissions() {
        driver.findElementByClassName("panel-title").click();
        sleep(1000);
        return new SystemSettingsPage(driver);
    }

}
