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

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class OrganizationIndexPage extends BasePage {

	private WebDriverWait wait = new WebDriverWait(driver,10);
	private WebElement organizationTable;
		
	public OrganizationIndexPage(WebDriver webdriver) {
		super(webdriver);
	 organizationTable = driver.findElementById("teamTable");
	}
	
	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("collapsed");
		
		if (bodyRows != null && bodyRows.size() == 1 && bodyRows.get(0).getText().trim().equals("No keys found.")) {
			return 0;
		}		
		
		return driver.findElementsByClassName("collapsed").size();
	}
	
	public OrganizationIndexPage clickAddOrganizationButton() {
		driver.findElementById("addTeamModalButton").click();
		//wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("myTeamModal")));
		return new OrganizationIndexPage(driver);
	}
	
	public OrganizationIndexPage addNewOrganization(String name){
		clickAddOrganizationButton();
		driver.findElementById("nameInput").sendKeys(name);
		driver.findElementById("submitTeamModal").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id("myTeamModal")));
		return new OrganizationIndexPage(driver);
	}
	
	public OrganizationIndexPage expandOrganizationRowByName(String name){
		for(int i=1;i<getNumRows();i++){
			if(driver.findElementById("teamName"+i).getText().contains(name)){
				driver.findElementById("teamName"+i).click();
			}
		}
		
		return new OrganizationIndexPage(driver);
	}
	public OrganizationIndexPage addNewApplication(String teamName, String appName, String url, String critic){
		driver.findElementById("teamName1").click();
		//int num = getAppValue();
		driver.findElementByLinkText("Add Application").click();
		//wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("myAppModal"+num)));
		driver.findElementsById("nameInput").get(1).sendKeys(appName);
		driver.findElementById("urlInput").sendKeys(url);
		new Select(driver.findElementById("criticalityId")).selectByVisibleText(critic);
		driver.findElementById("submitAppModal").click();
		//wait.until(ExpectedConditions.invisibilityOfElementLocated(By.className("modal")));
		return new OrganizationIndexPage(driver);
		
	}
	
	public int getAppValue(){
		Pattern p = Pattern.compile("id=\"addApplicationModalButton(\\d+)\"");
		String s = driver.findElementByLinkText("Add Application").getText();
		Matcher m = p.matcher(s);
		String find="0";
		if(m.find()){
			find = m.group(1);
		}
		return Integer.parseInt(find);
		
	}
	
	public OrganizationDetailPage clickViewTeamLink(String teamName){
		expandOrganizationRowByName(teamName);
		//should be changed to look for id
		driver.findElementByLinkText("View Team").click();
		return new OrganizationDetailPage(driver);
		
	}
	
	public ApplicationDetailPage clickApplicationDetailLink(String appName){
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
