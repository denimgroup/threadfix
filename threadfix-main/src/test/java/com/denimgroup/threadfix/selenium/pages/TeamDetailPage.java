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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class TeamDetailPage extends BasePage {
	
//	private WebElement orgName;
	private WebElement applicationsTableBody;
	private WebElement lastItemFoundInApplicationsTableBodyLink;
	private WebElement addApplicationLink;
	
	public TeamDetailPage(WebDriver webdriver) {
		super(webdriver);
		
//		orgName = driver.findElementById("name");
		applicationsTableBody = driver.findElementById("applicationsTableBody");
		addApplicationLink = driver.findElementByLinkText("Add Application");
	}
	
	public String getOrgName() {
		return driver.findElementById("name").getText();
	}
	
	
	public TeamDetailPage clickEditOrganizationLink() {
        driver.findElementById("actionButton").click();
        driver.findElementById("teamModalButton").click();
		waitForElement(driver.findElementById("teamModal"));
		return new TeamDetailPage(driver);
	}
	
	public TeamDetailPage setNameInput(String editedOrgName) {
		driver.findElementById("teamNameInput").clear();
		driver.findElementById("teamNameInput").sendKeys(editedOrgName);
		return new TeamDetailPage(driver);
	}
	
	public TeamDetailPage clickUpdateButtonValid() {
		driver.findElementById("submitTeamModal").click();
		try{
			waitForInvisibleElement(driver.findElementById("teamModal"));
		}catch(TimeoutException e){
			driver.findElementById("submitTeamModal").click();
		}
		return new TeamDetailPage(driver);
	}
	
	public TeamDetailPage clickUpdateButtonInvalid() {
		driver.findElementById("submitTeamModal").click();
		return new TeamDetailPage(driver);
	}
	
	public TeamDetailPage clickShowMore(){
		driver.findElementById("showDetailsLink").click();
		return new TeamDetailPage(driver);
	}
	
	public TeamIndexPage clickDeleteButton() {
		clickEditOrganizationLink();
		sleep(500);
		driver.findElementById("deleteLink").click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new TeamIndexPage(driver);
	}
	
	public boolean isTextPresentInApplicationsTableBody(String text) {
		for (WebElement element : applicationsTableBody.findElements(By.xpath(".//tr/td/a"))) {
			if (element.getText().contains(text)) {
				lastItemFoundInApplicationsTableBodyLink = element;
				return true;
			}
		}
		return false;
	}
	
	public TeamIndexPage clickExpandAll(){
		driver.findElementById("expandAllButton").click();
		return new TeamIndexPage(driver);
	}
	
	public TeamIndexPage clickCollapseAll(){
		driver.findElementById("collapseAllButton").click();
		return new TeamIndexPage(driver);
	}

	public ApplicationDetailPage clickTextLinkInApplicationsTableBody(String text) {
		if (isTextPresentInApplicationsTableBody(text)) {
			lastItemFoundInApplicationsTableBodyLink.click();
			return new ApplicationDetailPage(driver);
		} else {
			return null;
		}
	}
	
	public Map<String, Integer> getVulnCountForApps() {
		Map<String, Integer> map = new HashMap<>();
		
		// get app names
		List<WebElement> appLinks = applicationsTableBody.findElements(By.xpath(".//tr/td/a"));
		List<WebElement> counts   = applicationsTableBody.findElements(By.id("vulnCountCell"));
		
		if (appLinks.size() != counts.size()) {
			return null;
		}
		
		for (int i = 0; i < appLinks.size(); i++) {
			try {
				map.put(appLinks.get(i).getText(), Integer.valueOf(counts.get(i).getText()));
			} catch (NumberFormatException e) {
				e.printStackTrace();
			}
		}
		
		return map;
	}

	public ApplicationAddPage clickAddApplicationLink() {
		addApplicationLink.click();
		return new ApplicationAddPage(driver);
	}

	public String getErrorText() {
		return driver.findElementById("name.errors").getText().trim();
	}


}
