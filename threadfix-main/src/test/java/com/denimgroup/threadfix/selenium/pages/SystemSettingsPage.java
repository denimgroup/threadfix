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

    /*------------------------------ DEFAULT LDAP ROLE ------------------------------*/

    public SystemSettingsPage expandDefaultLDAPRole() {
        driver.findElementById("defaultPermissionsPanel").click();
        return new SystemSettingsPage(driver);
    }

    @Deprecated
    public SystemSettingsPage defaultPermissions() {
        driver.findElementByClassName("panel-title").click();
        sleep(1000);
        return new SystemSettingsPage(driver);
    }

    public SystemSettingsPage toggleDefaultRoleCheckbox() {
        driver.findElementById("globalGroupEnabledCheckbox").click();
        return this;
    }

    public SystemSettingsPage setRole(String role){
        new Select(driver.findElementById("roleSelect")).selectByVisibleText(role);
        return this;
    }

    /*------------------------------ LDAP SETTINGS ------------------------------*/

    public SystemSettingsPage expandLDAPSettings() {
        driver.findElementById("ldapSettingsPanel").click();
        return new SystemSettingsPage(driver);
    }

    public SystemSettingsPage setLDAPSearchBase(String searchBase) {
        driver.findElementById("activeDirectoryBase").clear();
        driver.findElementById("activeDirectoryBase").sendKeys(searchBase);
        return this;
    }

    public SystemSettingsPage setLDAPUserDN(String userDN) {
        driver.findElementById("activeDirectoryUsername").clear();
        driver.findElementById("activeDirectoryUsername").sendKeys(userDN);
        return this;
    }

    public SystemSettingsPage setLDAPPassword(String password) {
        driver.findElementById("activeDirectoryCredentials").clear();
        driver.findElementById("activeDirectoryCredentials").sendKeys(password);
        return this;
    }

    public SystemSettingsPage setLDAPUrl(String url) {
        driver.findElementById("activeDirectoryURL").clear();
        driver.findElementById("activeDirectoryURL").sendKeys(url);
        return this;
    }

    /*------------------------------ Proxy Settings ------------------------------*/

    public SystemSettingsPage expandProxySettings() {
        driver.findElementById("proxySettingsPanel").click();
        return new SystemSettingsPage(driver);
    }

    /*------------------------------ Session Timeout Settings ------------------------------*/

    public SystemSettingsPage expandSessionTimeoutSettings() {
        driver.findElementById("defaultSessionTimeoutPermissionsPanel").click();
        return new SystemSettingsPage(driver);
    }

    public SystemSettingsPage setTimeout(String timeout) {
        driver.findElementById("sessionTimeout").clear();
        driver.findElementById("sessionTimeout").sendKeys(timeout);
        return new SystemSettingsPage(driver);
    }

    /*------------------------------ Page Methods ------------------------------*/



	public SystemSettingsPage clickSaveChanges() {
		driver.findElementById("updateDefaultsButton").click();
		return new SystemSettingsPage(driver);
	}

    /*------------------------------ Boolean Methods ------------------------------*/

    public boolean isSaveSuccessful(){
        return driver.findElementByClassName("alert-success").getText().trim().contains("Configuration was saved successfully.");
    }
}
