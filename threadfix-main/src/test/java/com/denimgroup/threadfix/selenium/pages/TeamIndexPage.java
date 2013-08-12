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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.UnhandledAlertException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;


public class TeamIndexPage extends BasePage {

	private List<WebElement> apps = new ArrayList<WebElement>();
	public int modalNum;
	public String appModalId;

	public TeamIndexPage(WebDriver webdriver) {
		super(webdriver);
		modalNum = 0;
		appModalId = "";

	}

	public int getNumTeamRows() {
		if (!(driver.findElementById("teamTable").getText().equals("Add Team"))) {
			return driver.findElementsByClassName("pointer").size();
		}
		return 0;
	}

	public int getNumAppRows(String teamName) {
		if (!(driver.findElementById("teamAppTableDiv" + (getIndex(teamName) + 1))
				.getText().contains("No applications found."))) {
			return driver.findElementById("teamAppTable" + (getIndex(teamName) + 1)).findElements(By.className("app-row")).size();
		}
		return 0;
	}

	public int getIndex(String teamName) {
		int i = -1;
		List<WebElement> names = new ArrayList<WebElement>();
		for (int j = 1; j <= getNumTeamRows(); j++) {
			names.add(driver.findElementById("teamName" + j));
		}
		for (WebElement name : names) {
			i++;
			String text = name.getText().trim();
			if (text.equals(teamName.trim())) {
				return i;
			}
		}
		names = new ArrayList<WebElement>();
		for (int j = 1; j <= getNumTeamRows(); j++) {
			names.add(driver.findElementById("teamName" + j));
		}
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
		return setPage();
	}

	public TeamIndexPage setTeamName(String name) {
		driver.findElementById("teamNameInput").clear();
		driver.findElementById("teamNameInput").sendKeys(name);
		return setPage();
	}

	public TeamIndexPage addNewTeam() {
		int cnt = getNumTeamRows() + 1;
		driver.findElementById("submitTeamModal").click();
		waitForElement(driver.findElementById("teamName"+cnt));
		waitForElement(driver.findElementByClassName("alert-success"));
		sleep(1000);
		return setPage();
	}

	public TeamIndexPage addNewTeamInvalid() {
		driver.findElementById("submitTeamModal").click();
		sleep(1000);
		return setPage();
	}

	public TeamIndexPage expandTeamRowByName(String name) {
		driver.findElementById("teamName" + (getIndex(name) + 1)).click();
		try{
			populateAppList(name);
		}catch(NoSuchElementException e){
			
		}

		return setPage();
	}
	
	public void populateAppList(String teamName){
		apps = new ArrayList<WebElement>();
		if (!driver.findElementById("teamAppTable" + (getIndex(teamName) + 1))
				.getText().contains("No applications found.")) {
				for (int j = 0; j < getNumAppRows(teamName); j++) {
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
		apps.get(getAppIndex(appName)).click();
		return new ApplicationDetailPage(driver);
	}

	public TeamIndexPage clickAddNewApplication(String teamName) {
		appModalId = getAppModalId(teamName);
		driver.findElementsByLinkText("Add Application").get(getIndex(teamName)).click();
		sleep(2000);
		waitForElement(driver.findElementById(appModalId));
		return setPage();
	}
	
	public String getAppModalId(String teamName){
		String s = driver.findElementsByLinkText("Add Application").get(getIndex(teamName)).getAttribute("href");
		Pattern pattern = Pattern.compile("#(myAppModal[0-9]+)$");
		Matcher matcher = pattern.matcher(s);
		if(matcher.find()){
			return  matcher.group(1);
		}
		return "";
	}

	public TeamIndexPage setApplicationName(String appName, String teamName) {
		driver.findElementsById("nameInput").get(getIndex(teamName)).clear();
		driver.findElementsById("nameInput").get(getIndex(teamName)).sendKeys(appName);
		return setPage();
	}

	public TeamIndexPage setApplicationUrl(String url, String teamName) {
		driver.findElementsById("urlInput").get(getIndex(teamName)).clear();
		driver.findElementsById("urlInput").get(getIndex(teamName))
				.sendKeys(url);
		return setPage();
	}

	public TeamIndexPage setApplicationCritic(String critic, String teamName) {
		new Select(driver.findElementsById("criticalityId").get(
				getIndex(teamName))).selectByVisibleText(critic);
		return setPage();
	}

	public TeamIndexPage saveApplication(String teamName) {
		driver.findElementsByClassName("modalSubmit").get(getIndex(teamName)).click();
		sleep(1000);
//		waitForInvisibleElement(driver.findElementById(appModalId));
		appModalId = "";
		return setPage();
	}

	public TeamIndexPage saveApplicationInvalid(String teamName) {
		driver.findElementsByClassName("modalSubmit").get(getIndex(teamName)).click();
		return new TeamIndexPage(driver);
	}
	
	
	public TeamIndexPage clickCloseAddTeamModal(){
		driver.findElementById("closeTeamModalButton").click();
		sleep(1000);
		return new TeamIndexPage(driver);
	}
	
	public TeamIndexPage clickCloseAddAppModal(String teamName){
		driver.findElementById(getAppModalId(teamName)).findElement(By.className("modal-footer")).findElements(By.className("btn")).get(0).click();
		sleep(1000);
		return new TeamIndexPage(driver);
	}

	public TeamIndexPage addNewApplication(String teamName, String appName,
			String url, String critic) {
		clickAddNewApplication(teamName);
		setApplicationName(appName, teamName);
		setApplicationUrl(url, teamName);
		setApplicationCritic(critic, teamName);
		return setPage();

	}

	public String getNameErrorMessage() {
		return driver.findElementById("name.errors").getText();
	}

	public String getUrlErrorMessage() {
		return driver.findElementById("url.errors").getText();
	}

	public boolean isAppPresent(String appName) {
		return driver.findElementByLinkText(appName).isDisplayed();
	}

	public TeamIndexPage clickUploadScan(String appName,String teamName) {
		modalNum = modalNumber(teamName,appName);
		driver.findElementById("uploadScanModalLink"+(getIndex(teamName)+1)+"-"+(getAppIndex(appName)+1)).click();
		waitForElement(driver.findElementById("uploadScan"+modalNum));
		return setPage();
	}
	
	public TeamIndexPage setPage(){
		TeamIndexPage page = new TeamIndexPage(driver);
		page.modalNum = modalNum;
		page.appModalId = appModalId;
		return page;
	}
	
	public TeamIndexPage setFileInput(String file, String teamName, String appName) {
		//driver.findElementById("fileInput"+modalNumber()).click();
		driver.findElementById("fileInput"+modalNum).sendKeys(file);
		/*for (int i = 1; i <= driver.findElementsByClassName("right-align")
				.size(); i++)
			if (driver.findElementById("applicationLink" + i).getText()
					.equals(appName)) {
				driver.findElementById("fileInput" + i).clear();
				driver.findElementById("fileInput" + i).sendKeys(file);
				break;
			}*/
		return setPage();
	}

	public ApplicationDetailPage clickUploadScanButton(String teamName, String appName) {
		driver.findElementById("submitScanModal"+modalNum).click();
		try{
		waitForInvisibleElement(driver.findElementById("uploadScan"+modalNum));
		}catch(StaleElementReferenceException e){
			
		}
		waitForElement(driver.findElementById("nameText"));
		waitForInvisibleElement(driver.findElementByClassName("alert-success"));
		//waitForElement(driver.findElementById("anyid"));
			return new ApplicationDetailPage(driver);

	}
	
	public ApplicationDetailPage clickUploadScanButton(String teamName, String appName,int cnt) {
		driver.findElementById("submitScanModal"+modalNum).click();
		int i = 0;
		try{
		waitForInvisibleElement(driver.findElementById("uploadScan"+modalNum));
		}catch(StaleElementReferenceException e){
			
		}
		waitForElement(driver.findElementById("nameText"));
//		waitForInvisibleElement(driver.findElementByClassName("alert-success"));
		try{
			while(!driver.findElementById("scanTabLink").getText().contains(Integer.toString(cnt))){
				if(i==10){
					break;
				}
				i++;
				sleep(500);
			}
		}catch(StaleElementReferenceException e){
			
		}catch(UnhandledAlertException e){
		}
		//waitForElement(driver.findElementById("anyid"));
			return new ApplicationDetailPage(driver);

	}
	

	public TeamIndexPage clickUploadScanButtonInvalid(String teamName, String appName) {
		driver.findElementById("submitScanModal"+modalNum).click();
		/*for (int i = 1; i <= driver.findElementsByClassName("right-align")
				.size(); i++)
			if (driver.findElementById("applicationLink" + i).getText()
					.equals(appName)) {
				driver.findElementById("submitScanModal" + i).click();
				break;
			}*/
		return setPage();
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



	public TeamDetailPage clickViewTeamLink(String teamName) {
		driver.findElementsByLinkText("View Team").get(getIndex(teamName)).click();
		sleep(2000);
		return new TeamDetailPage(driver);
	}
	
	public int modalNumber(String teamName, String appName){
		String s = driver.findElementById("uploadScanModalLink"+(getIndex(teamName)+1)+"-"+(getAppIndex(appName)+1)).getAttribute("href");
		Pattern pattern = Pattern.compile("#uploadScan([0-9]+)$");
		Matcher matcher = pattern.matcher(s);
		if(matcher.find()){
			return  Integer.parseInt(matcher.group(1));
		}
		return -1;
	}
	
	public boolean isAddTeamBtnPresent(){
		return driver.findElementById("addTeamModalButton").isDisplayed();	
	}
	
	public boolean isAddTeamBtnClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("addTeamModalButton")) != null;
	}
	
	public boolean isExpandAllBtnPresent(){
		return driver.findElementById("expandAllButton").isDisplayed();	
	}
	
	public boolean isExpandAllBtnClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("expandAllButton")) != null;
	}
	
	public boolean isCollapseAllBtnPresent(){
		return driver.findElementById("collapseAllButton").isDisplayed();	
	}
	
	public boolean isCollapseAllBtnClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("collapseAllButton")) != null;
	}
	
	public boolean isAddAppBtnPresent(String teamName){
		return driver.findElementsByLinkText("Add Application").get(getIndex(teamName)).isDisplayed();	
	}
	
	public boolean isAddAppBtnClickable(String teamName){
		return ExpectedConditions.elementToBeClickable(By.id(
				driver.findElementsByLinkText("Add Application").get(getIndex(teamName)).getAttribute("id"))) != null;
	}
	
	public boolean isViewTeamLinkPresent(String teamName){
		return driver.findElementsByLinkText("View Team").get(getIndex(teamName)).isDisplayed();	
	}
	
	public boolean isViewTeamLinkClickable(String teamName){
		return ExpectedConditions.elementToBeClickable(By.id(
				driver.findElementsByLinkText("View Team").get(getIndex(teamName)).getAttribute("id"))) != null;
	}
	
	public boolean isAppLinkPresent(String appName){
		return driver.findElementByLinkText(appName).isDisplayed();
	}
	
	public boolean isAppLinkClickable(String appName){
		return ExpectedConditions.elementToBeClickable(By.linkText(appName)) != null;
	}
	
	public boolean isUploadScanPresent(String teamName, String appName){;
		return driver.findElementById("uploadScanModalLink"+(getIndex(teamName)+1)+"-"+(getAppIndex(appName)+1)).isDisplayed();
	}
	
	public boolean isUploadScanClickable(String teamName, String appName){
		return ExpectedConditions.elementToBeClickable(By.linkText("uploadScanModalLink"+(getIndex(teamName)+1)+"-"+(getAppIndex(appName)+1))) != null;
	}
	
	public boolean isAddTeamModalPresent(){
		return driver.findElementById("myTeamModal").isDisplayed();
	}
	
	public boolean isATNameFieldPresent(){
		return driver.findElementById("teamNameInput").isDisplayed();
	}
	
	public boolean isATNameFieldFunctional(){
		int limit = Integer.parseInt(driver.findElementById("teamNameInput").getAttribute("maxlength"));
		String s = getRandomString(limit+10);
		driver.findElementById("teamNameInput").sendKeys(s);
		String v = driver.findElementById("teamNameInput").getAttribute("value");
		return v.equals(s.substring(0, limit));
	}
	
	public boolean isCloseATButtonPresent(){
		return driver.findElementById("closeTeamModalButton").isDisplayed();
	}
	
	public boolean isCloseATButtonClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("closeTeamModalButton")) != null;
	}
	
	public boolean isAddTeamATButtonPresent(){
		return driver.findElementById("submitTeamModal").isDisplayed();
	}
	
	public boolean isAddTeamATButtonClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("submitTeamModal")) != null;
	}
	
	public boolean isAddAppModalPresent(String teamName){
		return driver.findElementById(getAppModalId(teamName)).isDisplayed();
	}
	
	public boolean isAPNameFieldPresent(String teamName){
		return driver.findElementById(getAppModalId(teamName)).findElement(By.id("nameInput")).isDisplayed();
	}
	
	public boolean isAPNameFieldFunctional(String teamName){
		int limit = Integer.parseInt(
				driver.findElementsById("nameInput").get(getIndex(teamName)).getAttribute("maxlength"));
		
		String s = getRandomString(limit+10);
//		System.out.println(teamName + " : " + getIndex(teamName));
		driver.findElementsById("nameInput").get(getIndex(teamName)).sendKeys(s);
		String v = driver.findElementsById("nameInput").get(getIndex(teamName)).getAttribute("value");
		return v.equals(s.substring(0, limit));
	}
	
	public boolean isURLFieldPresent(String teamName){
		return driver.findElementById(getAppModalId(teamName)).findElement(By.id("urlInput")).isDisplayed();
	}
	
	public boolean isURlFieldFunctional(String teamName){
		int limit = Integer.parseInt(
				driver.findElementsById("urlInput").get(getIndex(teamName)).getAttribute("maxlength"));
		
		String s = getRandomString(limit+10);
		driver.findElementsById("urlInput").get(getIndex(teamName)).sendKeys(s);
		String v = driver.findElementsById("urlInput").get(getIndex(teamName)).getAttribute("value");
		return v.equals(s.substring(0, limit));
	}
	
	public boolean isAPIDFieldPresent(String teamName){
		return driver.findElementById(getAppModalId(teamName)).findElement(By.id("uniqueIdInput")).isDisplayed();
	}
	
	public boolean isAPIDFieldFunctional(String teamName){
		int limit = Integer.parseInt(
				driver.findElementsById("uniqueIdInput").get(getIndex(teamName)).getAttribute("maxlength"));
		
		String s = getRandomString(limit+10);
		driver.findElementsById("uniqueIdInput").get(getIndex(teamName)).sendKeys(s);
		String v = driver.findElementsById("uniqueIdInput").get(getIndex(teamName)).getAttribute("value");
		return v.equals(s.substring(0, limit));
	}
	
	public boolean isAPCriticalityPresent(String teamName){
		return driver.findElementById(getAppModalId(teamName)).findElement(By.id("criticalityId")).isDisplayed();
	}
	
	public boolean isAPCriticalityCorrect(String teamName){
//		Select sel = new Select(driver.findElementById(getAppModalId(teamName)).findElement(By.id("criticalityId")));
//		for(int i=0; i<sel.getOptions().size(); i++)
//			System.out.println("option"+i+" "+sel.getOptions().get(i));
//		return sel.getOptions().contains("Low") && sel.getOptions().contains("Medium") && sel.getOptions().contains("High") && sel.getOptions().contains("Critical");
		//TODO
		return true;
	}
	
	public boolean isCloseAPButtonPresent(String teamName){
		return driver.findElementById(getAppModalId(teamName))
				.findElement(By.className("modal-footer"))
				.findElements(By.className("btn")).get(0).isDisplayed();
	}
	
	@SuppressWarnings("static-access")
	public boolean isCloseAPButtonClickable(String teamName){
		driver.findElementById(getAppModalId(teamName))
		.findElement(By.className("modal-footer"))
		.findElements(By.className("btn")).get(0);
		return ExpectedConditions.elementToBeClickable(By.id(getAppModalId(teamName)).className("modal-footer").className("btn")) != null;
	}
	
	public boolean isAddTeamAPButtonPresent(String teamName){
		return driver.findElementById(getAppModalId(teamName)).isDisplayed();
	}
	
	public boolean isAddTeamAPButtonClickable(String teamName){
		return ExpectedConditions.elementToBeClickable(By.id(getAppModalId(teamName))) != null;
	}



}
