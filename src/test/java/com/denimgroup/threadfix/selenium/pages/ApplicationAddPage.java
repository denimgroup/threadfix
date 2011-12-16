////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.selenium.pages;

import java.util.concurrent.TimeUnit;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * There are a lot of items here that are only there on certain conditions.
 * This code may break.
 * @author mcollins
 *
 */
public class ApplicationAddPage extends BasePage { 

	//safe
	private WebElement nameInput;
	private WebElement urlInput;
	private WebElement organizationText;
	private WebElement cancelLink;
	private WebElement addApplicationButton;
	
	public ApplicationAddPage(WebDriver webdriver) {
		super(webdriver);
		
		//safe
		nameInput = driver.findElementById("nameInput");
		urlInput = driver.findElementById("urlInput");
		organizationText = driver.findElementById("organizationText");
		cancelLink = driver.findElementById("cancelLink");
		addApplicationButton = driver.findElementById("addApplicationButton");
	}

	public String getNameInput(){
		return nameInput.getText();
	}

	public ApplicationAddPage setNameInput(String text){
		nameInput.clear();
		nameInput.sendKeys(text);
		return this;
	}
	
	public String getNameError() {
		return driver.findElementById("name.errors").getText();
	}

	public String getUrlInput(){
		return urlInput.getText();
	}

	public ApplicationAddPage setUrlInput(String text){
		urlInput.clear();
		urlInput.sendKeys(text);
		return this;
	}
	
	public String getUrlError() {
		return driver.findElementById("url.errors").getText();
	}

	public String getOrganizationText(){
		return organizationText.getText();
	}

	public OrganizationDetailPage clickCancelLink() {
		cancelLink.click();
		return new OrganizationDetailPage(driver);
	}
	public String getWafSelect(){
		return new Select(driver.findElementById("wafSelect")).getFirstSelectedOption().getText();
	}

	public ApplicationAddPage setWafSelect(String code){
		new Select(driver.findElementById("wafSelect")).selectByVisibleText(code);
		return this;
	}

	public WafIndexPage clickConfigureWafsButton() {
		driver.findElementById("configureWafsButton").click();
		return new WafIndexPage(driver);
	}
	
	public ApplicationAddPage clickJsonLink() {
		driver.findElementById("jsonLink").click();
		return this;
	}

	public String getProjectListSelect(){
		return new Select(driver.findElementById("projectList")).getFirstSelectedOption().getText();
	}

	public ApplicationAddPage setProjectListSelect(String code){
		 new Select(driver.findElementById("projectList")).selectByVisibleText(code);
		 return this;
	}

	public String getUserNameInput(){
		return driver.findElementById("username").getText();
	}

	public ApplicationAddPage setUserNameInput(String text){
		driver.findElementById("username").clear();
		driver.findElementById("username").sendKeys(text);
		return this;
	}

	public String getPasswordInput(){
		return driver.findElementById("password").getText();
	}

	public ApplicationAddPage setPasswordInput(String text){
		driver.findElementById("password").clear();
		driver.findElementById("password").sendKeys(text);
		return this;
	}

	public String getDefectTrackerIdSelect(){
		return new Select(driver.findElementById("defectTrackerId")).getFirstSelectedOption().getText();
	}

	public ApplicationAddPage setDefectTrackerIdSelect(String code){
		new Select(driver.findElementById("defectTrackerId")).selectByVisibleText(code);
		return this;
	}
	
	public ApplicationDetailPage clickAddApplicationButton() {
		addApplicationButton.click();
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationAddPage clickAddApplicationButtonInvalid() {
		addApplicationButton.click();
		return new ApplicationAddPage(driver);
	}
	
	public boolean isUserNameFieldEnabled() {
		return driver.findElementById("username").isEnabled();
	}
	
	public boolean isPasswordFieldEnabled() {
		return driver.findElementById("password").isEnabled();
	}
	
	public boolean isProductSelectEnabled() {
		return driver.findElementById("projectList").isEnabled();
	}
	
	public String getJsonResultText() {
		driver.manage().timeouts().implicitlyWait(20, TimeUnit.SECONDS);
		String result = driver.findElementById("jsonResult").getText();
		driver.manage().timeouts().implicitlyWait(NUM_SECONDS_TO_WAIT, TimeUnit.SECONDS);
		return result;
	}
	
	public String getSecondJsonResultText() {
		driver.manage().timeouts().implicitlyWait(20, TimeUnit.SECONDS);
		String result = driver.findElementById("jsonResult2").getText();
		driver.manage().timeouts().implicitlyWait(NUM_SECONDS_TO_WAIT, TimeUnit.SECONDS);
		return result;
	}
	
	public ApplicationAddPage waitForJsonResult() {
		driver.manage().timeouts().implicitlyWait(20, TimeUnit.SECONDS);
		System.out.println(driver.findElementById("jsonResult").getText());
		driver.manage().timeouts().implicitlyWait(NUM_SECONDS_TO_WAIT, TimeUnit.SECONDS);
		return this;
	}
}