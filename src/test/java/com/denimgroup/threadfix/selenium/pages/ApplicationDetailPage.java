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

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class ApplicationDetailPage extends BasePage {
	
	WebDriverWait wait = new WebDriverWait(driver,10);
	
	public ApplicationDetailPage(WebDriver webdriver) {
		super(webdriver);
	}
	
	public ApplicationDetailPage clickShowDetails(){
		driver.findElementById("showDetailsLink").click();
		waitForElement(driver.findElementById("appInfoDiv"));
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage addNewDefectTracker(String defectTrackerName, String defectTrackerURL, String defectTrackerType){
		clickShowDetails();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("appInfoDiv")));
		//TODO missing id
		driver.findElementByLinkText("Add Defect Tracker").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("addDTForm")));
		//TODO missing id
		driver.findElementByLinkText("Add Defect Tracker").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("createDefectTracker")));
		driver.findElementById("nameInput").sendKeys(defectTrackerName);
		driver.findElementById("urlInput").sendKeys(defectTrackerURL);
		new Select(driver.findElementById("defectTrackerTypeSelect")).selectByVisibleText(defectTrackerType);
		driver.findElementById("submitDTModal").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id("createDefectTracker")));
		//TODO currently does not allow you to add a defect tracker from application detail page
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage addDefectTracker(String defectTracker, String username, String password, String productname){
		clickShowDetails();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("appInfoDiv")));
		//TODO missing id
		driver.findElementByLinkText("Add Defect Tracker").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("addDTForm")));
		new Select(driver.findElementById("defectTrackerId")).selectByVisibleText(defectTracker);
		driver.findElementById("username").sendKeys(username);
		driver.findElementById("password").sendKeys(password);
		driver.findElementByLinkText("Test Connection").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("jsonResult")));
		new Select(driver.findElementById("projectList")).selectByVisibleText(productname);
		driver.findElementById("submitDTModal").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id("addDTForm")));
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage addNewWaf(String Name,String Type){
		clickShowDetails();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("appInfoDiv")));
		//TODO should be switched to id
		driver.findElementByLinkText("Add WAF").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("addWafForm")));
		driver.findElementByLinkText("Create New WAF").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("createWaf")));
		driver.findElementById("nameInput").sendKeys(Name);
		new Select(driver.findElementById("typeSelect")).selectByVisibleText(Type);
		driver.findElementById("submitTeamModal").click();
		//TODO currently does not allow you to add a waf from application detail page
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage addWaf(String wafName){
		Select s = new Select(driver.findElementById("wafSelect"));
		s.selectByVisibleText(wafName);
		driver.findElementById("submitTeamModal").click();
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickActionButton(){
		driver.findElementById("appActionButton").click();
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage addManualFinding(Boolean stat,String cwe,String url,String sourceFile,String lineNum,String Parameter,String Severity,String description){
		driver.findElementById("addManualFindinModalLink").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("addManualFinding")));
		if(stat){driver.findElementById("staticRadioButton").click();}
		driver.findElementById("txtSearch").sendKeys(cwe);
		driver.findElementById("urlDynamicSearch").sendKeys(url);
		driver.findElementById("urlStaticSearch").sendKeys(sourceFile);
		driver.findElementById("urlSearch").sendKeys(lineNum);
		driver.findElementById("parameterInput").sendKeys(Parameter);
		new Select(driver.findElementById("severityInput")).selectByVisibleText(Severity);
		driver.findElementById("descriptionInput").sendKeys(description);
		driver.findElementById("submitDTModal").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id("addManualFinding")));
		return new ApplicationDetailPage(driver);
	}
	public String getElementText(String id) {
		return driver.findElementById(id).getText();
	}
	
	public ApplicationDetailPage clickRefreshLink() {
		driver.findElementById("refreshLink").click();
		return new ApplicationDetailPage(driver);
	}
	
	public VulnerabilityPage clickVulnLink(int indexFromOne) {
		driver.findElementById("vulnName" + indexFromOne).click();
		return new VulnerabilityPage(driver);
	}
	
	public String getWafText(){
		waitForElement(driver.findElementById("wafText"));
		return driver.findElementById("wafText").getText();
	}
	
	public String getNameText(){
		return driver.findElementById("nameText").getText();
	}
	
	public String getUrlText(){
		return driver.findElementById("urlText").getText();
	}
	
	public String getDefectTrackerText() {
		return driver.findElementById("defectTrackerText").getText();
	}
	
	/*public String getOrganizationText(){
		return driver.findElementById("organizationText").getText();
	}*/
	
	public ApplicationEditPage clickEditLink() {
		clickActionButton();
		driver.findElementById("editLink").click();
		return new ApplicationEditPage(driver);
	}
	
	public TeamDetailPage clickTeamLink() {
		driver.findElementById("organizationText").click();
		sleep(300);
		return new TeamDetailPage(driver);
	}

	public TeamDetailPage clickDeleteLink() {
		clickActionButton();
		driver.findElementById("deleteLink").click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new TeamDetailPage(driver);
	}
	
	public ApplicationDetailPage clickDetailsLink(){
		clickActionButton();
		driver.findElementById("showDetailsLink").click();
		waitForElement(driver.findElementById("appInfoDiv"));
		return new ApplicationDetailPage(driver);
	}

	public ScanIndexPage clickViewScansLink() {
		driver.findElementById("viewScansLink").click();
		return new ScanIndexPage(driver);
	}

	public UploadScanPage clickUploadScanLink() {
		driver.findElementById("uploadScanLink").click();
		return new UploadScanPage(driver);
	}

	public ManualUploadPage clickAddFindingManuallyLink() {
		driver.findElementById("addFindingManuallyLink").click();
		return new ManualUploadPage(driver);
	}
	
	public int getNumRows() {
		return driver.findElementsByClassName("bodyRow").size();
	}

	public ApplicationDetailPage waitForScans() {
		
		ApplicationDetailPage returnPage = this;
		
		String appName = getNameText();
		
		returnPage = returnPage.clickTeamLink().clickTextLinkInApplicationsTableBody(appName);
		
		while (!isElementPresent("ajaxVulnTable")) {
			returnPage = returnPage.clickTeamLink().clickTextLinkInApplicationsTableBody(appName);
			sleep(2000);
		}
		return returnPage;
	}
	
	public ApplicationDetailPage clickEditWaf(){
		driver.findElementById("editWafButton").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("addWaf")));
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickAddWaf() {
		driver.findElementById("addWafButton").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("addWafForm")));
		return new ApplicationDetailPage(driver);
	}

}
