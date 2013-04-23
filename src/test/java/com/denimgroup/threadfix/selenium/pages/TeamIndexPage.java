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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class TeamIndexPage extends BasePage {

	private List<WebElement> names = new ArrayList<WebElement>();
	private List<WebElement> apps = new ArrayList<WebElement>();

	public TeamIndexPage(WebDriver webdriver) {
		super(webdriver);
		for (int i = 1; i <= getNumTeamRows(); i++) {
			names.add(driver.findElementById("teamName" + i));
		}

	}

	public int getNumTeamRows() {
		if (!(driver.findElementById("teamTable").getText().equals("Add Team"))) {
			return driver.findElementsByClassName("expandable").size();
		}
		return 0;
	}

	public int getNumAppRows(String teamName) {
		System.out.println("id = teamAppTable" + (getIndex(teamName) + 1));
		System.out.println(driver.findElementById("teamAppTable" + (getIndex(teamName) + 1))
				.getText());
		if (!(driver.findElementById("teamAppTable" + (getIndex(teamName) + 1))
				.getText().contains("No applications found."))) {
			return driver.findElementById("teamAppTable" + (getIndex(teamName) + 1)).findElements(By.className("app-row")).size();
		}
		return 0;
	}

	public int getIndex(String teamName) {
		int i = -1;
		for (WebElement name : names) {
			i++;
			String text = name.getText().trim();
			if (text.equals(teamName.trim())) {
				return i;
			}
		}
		return -1;
	}
	
	public int getAppIndex(String appName){
		int i = -1;
		for(WebElement app : apps){
			i++;
			String text = app.getText().trim();
			if(text.equals(appName.trim())){
				return i;
			}
		}
		return -1;
	}

	public TeamIndexPage clickAddTeamButton() {
		driver.findElementById("addTeamModalButton").click();
		waitForElement(driver.findElementById("myTeamModal"));
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage setTeamName(String name) {
		driver.findElementById("teamNameInput").clear();
		driver.findElementById("teamNameInput").sendKeys(name);
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage addNewTeam() {
		driver.findElementById("submitTeamModal").click();
		waitForInvisibleElement(driver.findElementById("myTeamModal"));
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage addNewTeamInvalid() {
		driver.findElementById("submitTeamModal").click();
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage expandTeamRowByName(String name) {
		driver.findElementById("teamName" + (getIndex(name) + 1)).click();

		return new TeamIndexPage(driver);
	}
	
	public void populateAppList(String teamName){
		apps = new ArrayList<WebElement>();
		if (!driver.findElementById("teamAppTable" + (getIndex(teamName) + 1))
				.getText().contains("No applications found.")) {
				for (int j = 0; j < getNumAppRows(teamName); j++) {
					System.out.println("team index " + getIndex(teamName)+" j "+j);
					apps.add(
							driver.findElementById(("applicationLink" + (getIndex(teamName) + 1))
									+ "-" + (j + 1)));
				}
		}
	}

	public boolean teamAddedToTable(String name) {
		return getIndex(name) != -1;
	}

	public ApplicationDetailPage clickViewAppLink(String appName, String teamName) {
		populateAppList(teamName);
		System.out.println("Num rows " + getNumAppRows(teamName));
		System.out.println("num apps " + apps.size());
		apps.get(getAppIndex(appName)).click();
		return new ApplicationDetailPage(driver);
	}

	public TeamIndexPage clickAddNewApplication(String teamName) {
		driver.findElementByLinkText("Add Application").click();
		waitForElement(driver.findElementByClassName("modal"));
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage setApplicationName(String appName, String teamName) {
		driver.findElementsById("nameInput").get(getIndex(teamName)).clear();
		driver.findElementsById("nameInput").get(getIndex(teamName))
				.sendKeys(appName);
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage setApplicationUrl(String url, String teamName) {
		driver.findElementsById("urlInput").get(getIndex(teamName)).clear();
		driver.findElementsById("urlInput").get(getIndex(teamName))
				.sendKeys(url);
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage setApplicationCritic(String critic, String teamName) {
		new Select(driver.findElementsById("criticalityId").get(
				getIndex(teamName))).selectByVisibleText(critic);
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage saveApplication() {
		driver.findElementByClassName("modal-footer")
				.findElement(By.linkText("Add Application")).click();
		waitForInvisibleElement(driver.findElementByClassName("modal"));
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage saveApplicationInvalid() {
		driver.findElementByClassName("modal-footer")
				.findElement(By.linkText("Add Application")).click();
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage addNewApplication(String teamName, String appName,
			String url, String critic) {
		expandTeamRowByName(teamName);
		clickAddNewApplication(teamName);
		setApplicationName(appName, teamName);
		setApplicationUrl(url, teamName);
		setApplicationCritic(critic, teamName);
		saveApplication();
		return new TeamIndexPage(driver);

	}

	public String getNameErrorMessage() {
		return driver.findElementById("name.errors").getText();
	}

	public String getUrlErrorMessage() {
		return driver.findElementById("url.errors").getText();
	}

	/*
	public ApplicationDetailPage clickApplicationDetailLink(String appName) {
		driver.findElementByLinkText(appName).click();
		return new ApplicationDetailPage(driver);
	}
	*/
	public boolean isAppPresent(String appName) {
		return driver.findElementByLinkText(appName).isDisplayed();
	}

	public TeamIndexPage clickUploadScan(String appName) {
		for (int i = 1; i <= driver.findElementsByClassName("right-align")
				.size(); i++)
			if (driver.findElementById("applicationLink" + i).getText()
					.equals(appName)) {
				driver.findElementsById("uploadScanModalLink").get(i - 1)
						.click();
				waitForElement(driver.findElementById("uploadScan" + i));
				break;
			}
		return new TeamIndexPage(driver);

	}

	public TeamIndexPage setFileInput(String file, String appName) {
		for (int i = 1; i <= driver.findElementsByClassName("right-align")
				.size(); i++)
			if (driver.findElementById("applicationLink" + i).getText()
					.equals(appName)) {
				driver.findElementById("fileInput" + i).clear();
				driver.findElementById("fileInput" + i).sendKeys(file);
				break;
			}
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage clickUploadScanButton(String appName) {
		for (int i = 1; i <= driver.findElementsByClassName("right-align")
				.size(); i++)
			if (driver.findElementById("applicationLink" + i).getText()
					.equals(appName)) {
				driver.findElementById("submitScanModal" + i).click();
				waitForInvisibleElement(driver
						.findElementById("uploadScan" + i));
				break;
			}
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage clickUploadScanButtonInvalid(String appName) {
		for (int i = 1; i <= driver.findElementsByClassName("right-align")
				.size(); i++)
			if (driver.findElementById("applicationLink" + i).getText()
					.equals(appName)) {
				driver.findElementById("submitScanModal" + i).click();
				break;
			}
		return new TeamIndexPage(driver);
	}

	public boolean isTeamPresent(String teamName) {
		return getIndex(teamName) != -1;
	}

	public boolean isCreateValidtionPresent(String teamName) {
		return driver
				.findElementByClassName("alert-success")
				.getText()
				.contains(
						"Team " + teamName + " has been created successfully.");
	}

}
