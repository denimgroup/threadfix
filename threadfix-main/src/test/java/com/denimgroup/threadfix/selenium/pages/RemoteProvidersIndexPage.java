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

import org.openqa.selenium.*;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;
import java.lang.reflect.Method;

import java.rmi.Remote;

public class RemoteProvidersIndexPage extends BasePage {

	public RemoteProvidersIndexPage(WebDriver webDriver) {
		super(webDriver);
	}

	/*------------------------------ Action Methods ------------------------------*/


    public RemoteProvidersIndexPage clickConfigureContrast(){
        driver.findElementById("configure0").click();
        waitForElement(driver.findElementById("myModalLabel"));
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clickConfigureQualys(){
		driver.findElementById("configure1").click();
		waitForElement(driver.findElementById("myModalLabel"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage clickConfigureVeracode(){
		driver.findElementById("configure4").click();
		waitForElement(driver.findElementById("myModalLabel"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage clickConfigureWhiteHat(){
		driver.findElementById("configure5").click();
		waitForElement(driver.findElementById("myModalLabel"));
		return new RemoteProvidersIndexPage(driver);
	}

    public RemoteProvidersIndexPage clickSubmitWait() {
        driver.findElementById("submit").click();
        sleep(6000);
        return new RemoteProvidersIndexPage(driver);
    }
	
	public RemoteProvidersIndexPage saveQualys(){
		driver.findElementById("submit").click();
        int i = 1;
        while(driver.findElements(By.id("configure0")).isEmpty() && i++ < 5) {
            sleep(20000);
        }
        waitForElement(driver.findElementById("configure0"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage closeModal(){
		driver.findElementById("closeModalButton").click();
        sleep(1000);
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage saveVera(){
		driver.findElementById("submit").click();
        waitForSuccessMessage();
        int i = 1;
        while(driver.findElements(By.id("clearConfig2")).isEmpty() && i++ < 5) {
            sleep(20000);
        }
		waitForElement(driver.findElementById("clearConfig2"));
		return new RemoteProvidersIndexPage(driver);
	}

    public RemoteProvidersIndexPage saveContrast(){
        driver.findElementById("submit").click();
        waitForSuccessMessage();
        int i = 1;
        while(driver.findElements(By.id("clearConfig4")).isEmpty() && i++ < 5) {
            sleep(20000);
        }
        waitForElement(driver.findElementById("clearConfig4"));
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage selectWhiteHatImportStyle() {
        driver.findElementByLinkText("WhiteHat").click();
        return this;
    }

	public RemoteProvidersIndexPage saveWhiteHat(){
        selectWhiteHatImportStyle();
		driver.findElementById("submit").click();
        waitForSuccessMessage();
        int i = 1;
        while(driver.findElements(By.id("clearConfig1")).isEmpty() && i++ < 5) {
            sleep(20000);
        }
        waitForElement(driver.findElementById("clearConfig1"));
		return new RemoteProvidersIndexPage(driver);
	}

    public RemoteProvidersIndexPage setContrastUser(String user) {
        driver.findElementById("Username").clear();
        driver.findElementById("Username").sendKeys(user);
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage setContrastAPI(String api) {
        driver.findElementById("API Key").clear();
        driver.findElementById("API Key").sendKeys(api);
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage setContrastService(String service) {
        driver.findElementById("Service Key").clear();
        driver.findElementById("Service Key").sendKeys(service);
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

    public RemoteProvidersIndexPage mapQualysToTeamAndApp(int appRow, String teamName, String appName) {
        clickEditMappingQualysButton(appRow);
        selectTeamMapping(teamName);
        selectAppMapping(appName);
        clickUpdateMappings();
        waitForElement(driver.findElementById("provider3import" + appRow));
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clickEditMappingQualysButton(int row) {
        driver.findElementById("provider3updateMapping" + row).click();
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clickEditMappingContrastButton(int row) {
        driver.findElementById("provider4updateMapping" + row).click();
        return new RemoteProvidersIndexPage(driver);
    }

	public RemoteProvidersIndexPage mapWhiteHatToTeamAndApp(int appRow, String teamName, String appName){
		clickEditWhiteHatButton(appRow);
        selectTeamMapping(teamName);
        selectAppMapping(appName);
		clickUpdateMappings();
        waitForElement(driver.findElementById("provider1import" + appRow));
		return new RemoteProvidersIndexPage(driver);
	}

	public RemoteProvidersIndexPage clickEditWhiteHatButton(int row){
		driver.findElementById("provider1updateMapping" + row).click();
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

    public ApplicationDetailPage clickWhiteHatImportScan(int appRow) {
        String elementToClick = "provider1import" + appRow;
        waitForElement(driver.findElementById(elementToClick));
        if (!tryClick(By.id(elementToClick))) {
            throw new ElementNotVisibleException(elementToClick);
        }
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickQualysGuardImportScan(int appRow) {
        String elementToClick = "provider3import" + appRow;
        waitForElement(driver.findElementById(elementToClick));
        if (!tryClick(By.id(elementToClick))) {
            throw new ElementNotVisibleException(elementToClick);
        }
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickContrastImportScan(int appRow) {
        String elementToClick = "provider4import" + appRow;
        waitForElement(driver.findElementById(elementToClick));
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

    public RemoteProvidersIndexPage mapVeracodeToTeamAndApp(int appRow, String teamName, String appName) {
        clickVeraCodeEditMappingButton(appRow);
        selectTeamMapping(teamName);
        selectAppMapping(appName);
        clickUpdateMappings();
        waitForElement(driver.findElementById("provider2import" + appRow));
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clickVeraCodeEditMappingButton(int appRow) {
        driver.findElementById("provider2updateMapping" + appRow).click();
        waitForElement(driver.findElementById("orgSelect1"));
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clickUpdateMappings(){
        driver.findElementById("submit").click();
        sleep(1000);
        return new RemoteProvidersIndexPage(driver);
    }

    public ApplicationDetailPage clickVeracodeImportScan(int appRow) {
        driver.findElementById("provider2import" + appRow).click();
        return new ApplicationDetailPage(driver);
    }

    public RemoteProvidersSchedulePage clickScheduleTab() {
        String linkText = driver.findElementById("scheduledImportTab").getAttribute("heading");
        driver.findElementByLinkText(linkText).click();

        waitForElement(driver.findElementById("addImportQueueLink"));
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

    public RemoteProvidersIndexPage clearPreviousWhiteHat() {
        if (driver.findElementById("clearConfig1").isDisplayed()) {
            driver.findElementById("clearConfig1").click();
            handleAlert();
            return new RemoteProvidersIndexPage(driver);
        }
        return new RemoteProvidersIndexPage(driver);
    }

    public RemoteProvidersIndexPage clickCloseButton() {
        driver.findElementById("closeModalButton").click();
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
        waitForElement(driver.findElementById("myModalLabel"));
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
        waitForElement(driver.findElementByClassName("alert-success"));
		return driver.findElementByClassName("alert-success").getText().trim();
	}

    /*------------------------------ Boolean Methods ------------------------------*/
    //Note: Qualys = 3, Veracode = 2, Whitehat = 1
    public boolean isMappingCorrect(int provider, int appRow, String teamName, String appName) {
        if(!driver.findElementById("provider"+ provider + "tfteamname" + appRow).getText().contains(teamName) ||
                !driver.findElementById("provider" + provider + "tfappname" + appRow).getText().contains(appName)) {
            return false;
        }
        return true;
    }

    public boolean isApplicationLinkPresent(String appName) {
        return driver.findElementsByLinkText(appName).size() != 0;
    }

    public boolean checkConfigurationMessage(int provider, String status) {
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

    //Todo: Create clear methods for remaining providers.
    public RemoteProvidersIndexPage ensureRemoteProviderConfigurationIsCleared(String provider) {
        String providerKey;
        switch (provider) {
            case "Contrast":
                providerKey = "0";
                break;
            case "QualysGuard":
                providerKey = "1";
                break;
            case "Sonatype":
                providerKey = "2";
                break;
            case "Hailstorm":
                providerKey = "3";
                break;
            case "Veracode":
                providerKey = "4";
                break;
            case "WhiteHat":
                providerKey = "5";
                break;
            case "WhiteHat Source":
                providerKey = "6";
                break;
            default:
                providerKey = null;
        }
        if (("Yes").equals(driver.findElementById("apiKey" + providerKey).getText().trim())) {
            switch (provider) {
                case ("Contrast"):
                    clearContrast();
                    break;
                case ("QualysGuard"):
                    clearQualys();
                    break;
                case ("Veracode"):
                    clearVeraCode();
                    break;
                case ("WhiteHat"):
                    clearWhiteHat();
                    break;
                default:
                    System.out.println("Method to clear provider doesn't exist.");
            }
        }
        return new RemoteProvidersIndexPage(driver);
    }
}