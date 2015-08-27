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

import org.openqa.selenium.*;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class RemoteProvidersIndexPage extends BasePage {

	public RemoteProvidersIndexPage(WebDriver webDriver) {
		super(webDriver);
	}

	/*------------------------------ Action Methods ------------------------------*/

    public RemoteProvidersIndexPage clickConfigure(String provider) {
        driver.findElementById("configure" + provider).click();
        waitForElement(By.id("myModalLabel"));
        return new RemoteProvidersIndexPage(driver);
    }
	
	public RemoteProvidersIndexPage closeModal(){
		driver.findElementById("closeModalButton").click();
        sleep(1000);
		return new RemoteProvidersIndexPage(driver);
	}

    public RemoteProvidersIndexPage saveConfiguration(String provider) {
        driver.findElementById("submit").click();
        waitForInvisibleElement("myModalLabel");
        waitForElement(By.id("clearConfig" + provider), 45);
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage selectWhiteHatImportStyle() {
        driver.findElementByLinkText("WhiteHat").click();
        return this;
    }

    public RemoteProvidersIndexPage setContrastUser(String user) {
        driver.findElementById("Username").clear();
        driver.findElementById("Username").sendKeys(user);
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage setContrastAPI(String api) {
        driver.findElementById("APIKey").clear();
        driver.findElementById("APIKey").sendKeys(api);
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage setContrastService(String service) {
        driver.findElementById("ServiceKey").clear();
        driver.findElementById("ServiceKey").sendKeys(service);
        return new RemoteProvidersIndexPage(driver);
    }

	public RemoteProvidersIndexPage setQualysUsername(String user){
		driver.findElementById("usernameInput").clear();
		driver.findElementById("usernameInput").sendKeys(user);
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setQualysPassword(String password){
		driver.findElementById("passwordInput").clear();
		driver.findElementById("passwordInput").sendKeys(password);
		return new RemoteProvidersIndexPage(driver);
	}

    public RemoteProvidersIndexPage setQualysPlatform(String platform) {
        driver.findElementById("platformNameSelect").sendKeys(platform);
        return this;
    }
	
	public RemoteProvidersIndexPage setQualysUS(){
		driver.findElementById("isEuropean1").click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setQualysEU(){
		driver.findElementById("isEuropean2").click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setVeraUsername(String user){
		driver.findElementById("usernameInput").clear();
		driver.findElementById("usernameInput").sendKeys(user);
		return this;
	}
	
	public RemoteProvidersIndexPage setVeraPassword(String password){
		driver.findElementById("passwordInput").clear();
		driver.findElementById("passwordInput").sendKeys(password);
		return this;
	}
	
	public RemoteProvidersIndexPage setWhiteHatAPI(String api){
		driver.findElementById("apiKeyInput").clear();
		driver.findElementById("apiKeyInput").sendKeys(api);
		return this;
	}

    public RemoteProvidersIndexPage mapProviderToTeamAndApp(String provider, int appRow, String teamName, String appName) {
        clickEditMappingButton(provider, appRow);
        selectTeamMapping(teamName);
        selectAppMapping(appName);
        clickUpdateMappings();
        waitForElement(By.id("provider" + provider + "import" + appRow));
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clickEditMappingButton(String provider, int row) {
        driver.findElementById("provider" + provider + "updateMapping" + row).click();
        return new RemoteProvidersIndexPage(driver);
    }
	
	public RemoteProvidersIndexPage selectTeamMapping(String teamName){
		WebElement webElement = driver.findElementById("orgSelect1");
		new Select(webElement).selectByVisibleText(teamName);
		return this;
	}

	public RemoteProvidersIndexPage selectAppMapping(String appName){
		WebElement webElement = driver.findElementById("appSelect1");
		new Select(webElement).selectByVisibleText(appName);
		return this;
	}

    public ApplicationDetailPage clickImportScan(String provider, int appRow) {
        String elementToClick = "provider" + provider + "import" + appRow;
        waitForElement(By.id(elementToClick));
        if (!tryClick(By.id(elementToClick))) {
            throw new ElementNotVisibleException(elementToClick);
        }
        return new ApplicationDetailPage(driver);
    }

    public TeamDetailPage clickTeamLink(String teamName) {
        driver.findElementByLinkText(teamName).click();
        return new TeamDetailPage(driver);
    }

    public ApplicationDetailPage clickApplicationLink(String appName) {
        driver.findElementByLinkText(appName).click();
        return new ApplicationDetailPage(driver);
    }

    public RemoteProvidersIndexPage clickUpdateMappings(){
        driver.findElementById("submit").click();
        sleep(1000);
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersSchedulePage clickScheduleTab() {
        String linkText = driver.findElementById("scheduledImportTab").getAttribute("heading");
        driver.findElementByLinkText(linkText).click();

        waitForElement(By.id("addImportQueueLink"));
        return new RemoteProvidersSchedulePage(driver);
    }

	public String getErrorMessage(){
        waitForElementPresence("errorSpan", 60);
		return driver.findElementById("errorSpan").getText();
	}
	
	public RemoteProvidersIndexPage clearWhiteHat(){
		driver.findElementById("clearConfig1").click();
		handleAlert();
		return new RemoteProvidersIndexPage(driver);
	}

    public RemoteProvidersIndexPage clickCloseButton() {
        driver.findElementById("closeModalButton").click();
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clearConfiguration(String provider) {
        driver.findElementById("clearConfig" + provider).click();
        handleAlert();
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clearContrast() {
        driver.findElementById("clearConfig4").click();
        handleAlert();
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clearVeraCode() {
        driver.findElementById("clearConfig2").click();
        handleAlert();
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clearQualys() {
        driver.findElementById("clearConfig3").click();
        handleAlert();
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clickEditName(String provider, String appNum) {
        driver.findElementById("provider" + provider + "updateName" + appNum).click();
        waitForElement(By.id("myModalLabel"));
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage setNewName(String name) {
        driver.findElementById("customName").clear();
        driver.findElementById("customName").sendKeys(name);
        driver.findElementById("submit").click();
        sleep(500);
        return new RemoteProvidersIndexPage(driver);
    }

	public String successAlert(){
        waitForElement(By.className("alert-success"));
		return driver.findElementByClassName("alert-success").getText().trim();
	}

    /*------------------------------ Boolean Methods ------------------------------*/
    //Note: Qualys = 3, Veracode = 2, Whitehat = 1
    public boolean isMappingCorrect(String provider, int appRow, String teamName, String appName) {
        if(!driver.findElementById("provider"+ provider + "tfteamname" + appRow).getText().contains(teamName) ||
                !driver.findElementById("provider" + provider + "tfappname" + appRow).getText().contains(appName)) {
            return false;
        }
        return true;
    }

    public boolean isApplicationLinkPresent(String appName) {
        return driver.findElementsByLinkText(appName).size() != 0;
    }

    public boolean checkConfigurationMessage(String provider, String status) {
        return driver.findElementById("apiKey" + provider).getText().contains(status);
    }

    public boolean isTeamLinkPresent(String teamName) {
        return driver.findElementsByLinkText(teamName).size() != 0;
    }

    public boolean isTabPresent() {
        return driver.findElementById("remoteProvidersTab").isDisplayed();
    }

    public boolean isSuccessMessagePresent(String expectedMessage) {
        return driver.findElementByClassName("alert-success").getText()
                .contains(expectedMessage);
    }

    /*-------------------------------- String Methods --------------------------------*/

    public String getAppName(String provider, String appNum) {
        return driver.findElementById("provider" + provider + "appid" + appNum).getText();
    }

    public String getModalText() {
        return driver.findElementById("myModalLabel").getText();
    }

    /*-------------------------------- Helper Methods --------------------------------*/

    public void waitForErrorMessage() {
        sleep(5000);
    }

    public void waitForSuccessMessage() {
        try {
            WebDriverWait wait = new WebDriverWait(driver, 60);
            wait.until(ExpectedConditions.presenceOfElementLocated(By.className("alert-success")));
        } catch (TimeoutException e) {
            throw new RuntimeException("Success message was not shown as it should have been.", e);
        }
    }

    public RemoteProvidersIndexPage ensureRemoteProviderConfigurationIsCleared(String provider) {
        if (("Yes").equals(driver.findElementById("apiKey" + provider).getText().trim())) {
            clearConfiguration(provider);
        }
        return new RemoteProvidersIndexPage(driver);
    }
}