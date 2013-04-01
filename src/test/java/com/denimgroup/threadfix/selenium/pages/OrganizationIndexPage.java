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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class OrganizationIndexPage extends BasePage {

	private WebElement addTeamButton;
	private WebDriverWait wait = new WebDriverWait(driver,10);
		
	public OrganizationIndexPage(WebDriver webdriver) {
		super(webdriver);
		//organizationTable = driver.findElementById("teamTable");
		addTeamButton = driver.findElementById("addTeamModalButton");
	}
	
	public OrganizationIndexPage clickAddOrganizationButton() {
		addTeamButton.click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("myTeamModal")));
		return new OrganizationIndexPage(driver);
	}
	
	public OrganizationIndexPage addNewOrganization(String name){
		driver.findElementById("nameInput").sendKeys(name);
		driver.findElementById("subitTeamModal").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id("myTeamModal")));
		return new OrganizationIndexPage(driver);
	}
	
	public OrganizationIndexPage expandOrganizationRowByName(String name){
		WebElement table = driver.findElementById("teamTable");
		//need missing ids for name field in table
		return new OrganizationIndexPage(driver);
	}
	
	public OrganizationIndexPage addNewApplication(String teamName, String appName, String url, String critic){
		expandOrganizationRowByName(teamName);
		driver.findElementByLinkText("Add Application").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.className("modal")));
		driver.findElementById("Name").sendKeys(appName);
		driver.findElementById("urlInput").sendKeys(url);
		new Select(driver.findElementById("criticalityId")).selectByVisibleText(critic);
		driver.findElementById("submitAppModal").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.className("modal")));
		return new OrganizationIndexPage(driver);
	}
	
	public OrganizationDetailPage clickViewTeamLink(String teamName){
		expandOrganizationRowByName(teamName);
		//should be changed to look for id
		driver.findElementByLinkText("View Team").click();
		return new OrganizationDetailPage(driver);
		
	}
	
	public ApplicationDetailPage clickApplicationDetailLink(String teamName,String appName){
		expandOrganizationRowByName(teamName);
		driver.findElementByLinkText(appName).click();
		return new ApplicationDetailPage(driver);
	}
	
	/*needs to be redone when ids are added for organization name
	public boolean isOrganizationNamePresent(String organizationName) {
	
		for (WebElement element : organizationTable.findElements(By.xpath(".//tr/td/a"))) {
			if (element.getText().contains(organizationName)) {
				lastOrganizationFoundInTableLink = element;
				return true;
			}
		}
		
		return false;
	}*/
		
	public UserChangePasswordPage clickChangePasswordLinkIfPresent() {
		if (driver.findElementById("changePasswordLink") != null) {
			driver.findElementById("changePasswordLink").click();
			return new UserChangePasswordPage(driver);
		} else {
			return null;
		}
	}
}
