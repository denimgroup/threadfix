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

public class TeamIndexPage extends BasePage {

	private WebDriverWait wait = new WebDriverWait(driver,10);
	private WebElement teamTable;
		
	public TeamIndexPage(WebDriver webdriver) {
		super(webdriver);
		teamTable = driver.findElementById("teamTable");
	}
	
	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("collapsed");
		
		if (bodyRows != null && bodyRows.size() == 1 && bodyRows.get(0).getText().trim().equals("No keys found.")) {
			return 0;
		}		
		
		return driver.findElementsByClassName("collapsed").size();
	}
	
	public TeamIndexPage clickAddTeamButton() {
		driver.findElementById("addTeamModalButton").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("myTeamModal")));
		return new TeamIndexPage(driver);
	}
	
	public TeamIndexPage addNewTeam(String name){
		driver.findElementById("teamNameInput").sendKeys(name);
		driver.findElementById("submitTeamModal").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id("myTeamModal")));
		return new TeamIndexPage(driver);
	}
	
	public TeamIndexPage expandTeamRowByName(String name){
		//getNumRows() does not work after adding application, should change 10 to a more accurate function
		for(int i=1;i<10;i++){
			if(driver.findElementById("teamName"+i).getText().contains(name)){
				driver.findElementById("teamName"+i).click();
				break;
			}
		}
		
		return new TeamIndexPage(driver);
	}
	
	public TeamIndexPage expandTeamRow(int row){
		driver.findElementById("teamName"+row).click();
		return new TeamIndexPage(driver);
	}
	
	public boolean teamAddedToTable(String name){
	
		return driver.findElementById("teamTable").getText().contains(name);
	}
	
	public TeamDetailPage clickViewTeamLink(){
		driver.findElementByClassName("in").findElement(By.linkText("View Team")).click();
		return new TeamDetailPage(driver);
	}
	public TeamIndexPage addNewApplication(String teamName, String appName, String url, String critic){
		driver.findElementById("teamName1").click();
		int num = getAppValue();
		driver.findElementByLinkText("Add Application").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("myAppModal"+num)));
		sleep(1000);
		driver.findElementById("nameInput").sendKeys(appName);
		driver.findElementById("urlInput").sendKeys(url);
		new Select(driver.findElementById("criticalityId")).selectByVisibleText(critic);
		driver.findElementById("submitAppModal"+num).click();
		//wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id("myAppModal"+num)));
		return new TeamIndexPage(driver);
		
	}
	
	public int getAppValue(){
		Pattern p = Pattern.compile("addApplicationModalButton(\\d+)");
		String s = driver.findElementByLinkText("Add Application").getAttribute("id");
		Matcher m = p.matcher(s);
		String find="0";
		if(m.find()){
			find = m.group(1);
		}
		return Integer.parseInt(find);
		
	}
	
	
	public TeamDetailPage clickViewTeamLink(String teamName){
		expandTeamRowByName(teamName);
		//should be changed to look for id
		driver.findElementByLinkText("View Team").click();
		return new TeamDetailPage(driver);
		
	}
	
	public String getNameErrorMessage(){
		return driver.findElementById("name.errors").getText();
	}
	
	public String getUrlErrorMessage(){
		return driver.findElementById("url.errors").getText();
	}
	
	
	public ApplicationDetailPage clickApplicationDetailLink(String appName){
		driver.findElementByLinkText(appName).click();
		return new ApplicationDetailPage(driver);
	}
	
	
	public TeamIndexPage closeModal(){
		driver.findElementById("teamTable").click();
		return new TeamIndexPage(driver);
	}
	
	public boolean isAppPresent(String appName){
		return driver.findElementByLinkText(appName).isDisplayed();
	}
		
	public UserChangePasswordPage clickChangePasswordLinkIfPresent() {
		if (driver.findElementById("changePasswordLink") != null) {
			driver.findElementById("changePasswordLink").click();
			return new UserChangePasswordPage(driver);
		} else {
			return null;
		}
	}

	public boolean isOrganizationNamePresent(String OrgName) {
		
		return driver.findElementById("main-content").getText().contains(OrgName);
	}

	public TeamIndexPage clickSubmitButtonInvalid() {
		driver.findElementById("submitTeamModal").click();
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage setNameInput(String name) {
		driver.findElementById("teamNameInput").clear();
		driver.findElementById("teamNameInput").sendKeys(name);
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage clickSubmitButtonValid() {
		driver.findElementById("submitTeamModal").click();
		return new TeamIndexPage(driver);
	}

	public String getTeamName(int i) {
		return driver.findElementById("teamName"+i).getText().trim();
	}
	
}
