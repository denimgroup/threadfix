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
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class TeamDetailPage extends BasePage {
	
	private WebElement orgName;
	private WebElement backToList;
	private WebElement deleteButton;
	private WebElement editOrganizationLink;
	private WebElement applicationsTableBody;
	private WebElement lastItemFoundInApplicationsTableBodyLink;
	private WebElement addApplicationLink;
	
	public TeamDetailPage(WebDriver webdriver) {
		super(webdriver);
		
		orgName = driver.findElementById("name");
		backToList = driver.findElementById("backToList");
		deleteButton = driver.findElementById("deleteLink");
		editOrganizationLink = driver.findElementById("editOrganizationLink");
		applicationsTableBody = driver.findElementById("applicationsTableBody");
		addApplicationLink = driver.findElementById("addApplicationLink");
	}
	
	public String getOrgName() {
		return orgName.getText();
	}
	
	public TeamIndexPage clickBackToList() {
		backToList.click();
		return new TeamIndexPage(driver);
	}
	public OrganizationEditPage clickEditOrganizationLink() {
		editOrganizationLink.click();
		return new OrganizationEditPage(driver);
	}
	
	public TeamIndexPage clickDeleteButton() {
		deleteButton.click();
		
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

	public ApplicationDetailPage clickTextLinkInApplicationsTableBody(String text) {
		if (isTextPresentInApplicationsTableBody(text)) {
			lastItemFoundInApplicationsTableBodyLink.click();
			return new ApplicationDetailPage(driver);
		} else {
			return null;
		}
	}
	
	public Map<String, Integer> getVulnCountForApps() {
		Map<String, Integer> map = new HashMap<String,Integer>();
		
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
}
