////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class RemoteProvidersIndexPage extends BasePage {
	/*private List<WebElement> name = new ArrayList<WebElement>();
	private List<WebElement> userName = new ArrayList<WebElement>();
	private List<WebElement> apiKey = new ArrayList<WebElement>();
	private List<WebElement> configureButton = new ArrayList<WebElement>();

	private List<WebElement> appName = new ArrayList<WebElement>();
	private List<WebElement> appTeam = new ArrayList<WebElement>();
	private List<WebElement> appApplication = new ArrayList<WebElement>();
	private List<WebElement> appEditLink = new ArrayList<WebElement>();
	private List<WebElement> appImportScanLinks = new ArrayList<WebElement>();
	private List<WebElement> updateAppsLink = new ArrayList<WebElement>();
	private List<WebElement> clearConfig = new ArrayList<WebElement>();
*/
	private WebElement qualysConfigButton;
	private WebElement veracodeConfigButton;
	private WebElement whiteHateConfigButton;
	public RemoteProvidersIndexPage(WebDriver webDriver) {
		super(webDriver);
		qualysConfigButton = driver.findElementById("configure1");
		veracodeConfigButton = driver.findElementById("configure2");
		whiteHateConfigButton = driver.findElementById("configure3");
/*
		for (int i = 1; i <= getNumEdit(); i++) {
			name.add(driver.findElementById("name" + i));
			userName.add(driver.findElementById("username" + i));
			apiKey.add(driver.findElementById("apiKey" + i));
			configureButton.add(driver.findElementById("configure" + i));
			
			if (!driver.findElementById("username"+i).getText().equals("")
					|| !driver.findElementById("apiKey"+i).getText().equals("")) {
				
				updateAppsLink.add(driver.findElementById("updateApps"+i));
				clearConfig.add(driver.findElementById("clearConfig"+i));
				for (int j = 1; j <= getNumRows(); j++) {
					
					appName.add(driver.findElementById("provider" + i + "appid" + j));
					appTeam.add(driver.findElementById("provider" + i + "tfteamname"
							+ j));
					appApplication.add(driver.findElementById("provider" + i + "tfappname" + j));
					appEditLink.add(driver.findElementById("provider" + i + "updateMapping" + j));

					if (driver.findElementById("provider" + i + "tfteamname" + j)
							.getText().equals("")) {

					} else
						appImportScanLinks.add(driver
								.findElementById("provider" + i + "import" + j));

				}
			}
		}*/
	}
	
	public RemoteProvidersIndexPage clickConfigureQualys(){
		qualysConfigButton.click();
		waitForElement(driver.findElementById("remoteProviderEditModal3"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage clickConfigureVeracode(){
		veracodeConfigButton.click();
		waitForElement(driver.findElementById("remoteProviderEditModal2"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage clickConfigureWhiteHat(){
		whiteHateConfigButton.click();
		waitForElement(driver.findElementById("remoteProviderEditModal1"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setQualysUsername(String user){
		driver.findElementsById("usernameInput").get(0).clear();
		driver.findElementsById("usernameInput").get(0).sendKeys(user);
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setQualysPassword(String password){
		driver.findElementsById("passwordInput").get(0).clear();
		driver.findElementsById("passwordInput").get(0).sendKeys(password);
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setQualysUS(){
		driver.findElementById("isEuropean1").click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setQualysEU(){
		driver.findElementById("isEuropean2").click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage saveQualys(){
		driver.findElementById("submitRemoteProviderFormButton3").click();
		waitForInvisibleElement(driver.findElementById("remoteProviderEditModal3"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage saveQualysInvalid(){
		driver.findElementById("submitRemoteProviderFormButton3").click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage closeModal(){
		driver.findElementByClassName("modal-footer").findElement(By.className("btn")).click();
		waitForInvisibleElement(driver.findElementByClassName("modal"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setVeraUsername(String user){
		driver.findElementsById("usernameInput").get(1).clear();
		driver.findElementsById("usernameInput").get(1).sendKeys(user);
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage setVeraPassword(String password){
		driver.findElementsById("passwordInput").get(1).clear();
		driver.findElementsById("passwordInput").get(1).sendKeys(password);
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage saveVera(){
		driver.findElementById("submitRemoteProviderFormButton2").click();
		waitForInvisibleElement(driver.findElementById("remoteProviderEditModal3"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage saveVeraInvalid(){
		driver.findElementById("submitRemoteProviderFormButton2").click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	// WhiteHat Methods
	public RemoteProvidersIndexPage setWhiteHatAPI(String api){
		driver.findElementById("apiKeyInput").clear();
		driver.findElementById("apiKeyInput").sendKeys(api);
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage saveWhiteHat(){
		driver.findElementById("submitRemoteProviderFormButton1").click();
		waitForInvisibleElement(driver.findElementById("remoteProviderEditModal3"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage saveWhiteHatInvalid(){
		driver.findElementById("submitRemoteProviderFormButton1").click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage mapWhiteHatToTeamAndApp(int appRow, String team, String app){
		clickEditWhiteHatButton(appRow);
		selectTeamModal(team);
		selectAppModal(app);
		saveMappingWhiteHat();
		return new RemoteProvidersIndexPage(driver);
	}

	public RemoteProvidersIndexPage saveMappingWhiteHat(){
		driver.findElementByClassName("modal-footer").findElement(By.linkText("Update Application")).click();
		waitForInvisibleElement(driver.findElementByClassName("modal"));
		return new RemoteProvidersIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage clickEditWhiteHatButton(int row){
		driver.findElementById("provider3updateMapping" + row).click();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public UserIndexPage selectTeamModal(String role){
		WebElement a = driver.findElementById("orgSelect1");
		new Select(a).selectByVisibleText(role);
		return new UserIndexPage(driver);
	}
	
	
	public UserIndexPage selectAppModal(String role){
		WebElement a = driver.findElementById("appSelect1");
		new Select(a).selectByVisibleText(role);
		return new UserIndexPage(driver);
	}
	
	public String getErrorMessage(){
		return driver.findElementByClassName("alert-error").getText();
	}
	
	public RemoteProvidersIndexPage clearWhiteHat(){
		driver.findElementById("clearConfig3").click();
		handleAlert();
		return new RemoteProvidersIndexPage(driver);
	}
	
	public String successAlert(){
		return driver.findElementByClassName("alert-success").getText();
	}
	
//old methods
/*	
	public int getNumEdit() {
		return driver.findElementsByLinkText("Configure").size();

	}

	public int getNumRows() {
		return driver.findElementsByLinkText("Edit Mapping").size();
	}

	public String getNames(int num) {
		return name.get(num).getText();

	}

	public String getUsernames(int num) {
		return userName.get(num).getText();

	}

	public String getAPIKey(int num) {
		return apiKey.get(num).getText();

	}

	public RemoteProviderCredentialsPage clickConfigure(int Row) {
		configureButton.get(Row).click();
		sleep(1000);
		return new RemoteProviderCredentialsPage(driver);
	}

	public EditMappingPage clickEdit(int Row) {
		appEditLink.get(Row).click();
		sleep(1000);
		return new EditMappingPage(driver);
	}

	public void clickImport(int Row) {
		appImportScanLinks.get(Row).click();
		sleep(1000);
	}

	public void clickUpdate(int Row) {
		//UpdateAppsLink = driver.findElementById("updateApps1");
		updateAppsLink.get(Row).click();
		sleep(1000);
	}

	public RemoteProvidersIndexPage clickClearConfigButton(int rowNumber) {
		clearConfig.get(rowNumber).click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new RemoteProvidersIndexPage(driver);
	}
*/
}