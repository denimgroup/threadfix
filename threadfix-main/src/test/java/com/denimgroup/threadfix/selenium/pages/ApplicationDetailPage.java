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


import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class ApplicationDetailPage extends BasePage {

	WebDriverWait wait = new WebDriverWait(driver, 10);

	public ApplicationDetailPage(WebDriver webdriver) {
		super(webdriver);
	}

	public ApplicationDetailPage clickShowDetails() {
		driver.findElementById("showDetailsLink").click();
		waitForElement(driver.findElementById("appInfoDiv"));
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickAddDefectTrackerButton() {
		driver.findElementById("addDefectTrackerButton").click();
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage setUsername(String dtName) {
		driver.findElementById("username").clear();
		driver.findElementById("username").sendKeys(dtName);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage testClickApp(int num) {
		driver.findElementById("appLink" + num).click();
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickEditDefectTrackerButton() {
		driver.findElementById("editDefectTrackerButton").click();
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage setPassword(String dtPass) {
		driver.findElementById("password").clear();
		driver.findElementById("password").sendKeys(dtPass);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickTestConnection() {
		driver.findElementById("jsonLink").click();
		waitForElement(driver.findElementById("jsonResult"));
		sleep(2000);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage selectProduct(String product) {
		new Select(driver.findElementById("projectList"))
				.selectByVisibleText(product);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage selectDefectTracker(String defectTracker) {
		new Select(driver.findElementById("defectTrackerId"))
				.selectByVisibleText(defectTracker);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickSubmitTrackerButton() {
		driver.findElementById("submitDTModal").click();
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage addNewDefectTracker(String defectTrackerName,
			String defectTrackerURL, String defectTrackerType) {
		// clickShowDetails().clickAddDefectTrackerButton().setUsername(defectTrackerName).setUrlInput(defectTrackerURL).selectProduct()
		return new ApplicationDetailPage(driver);
		/*
		 * wait.until(ExpectedConditions.visibilityOfElementLocated(By.id(
		 * "appInfoDiv"))); //TODO missing id
		 * driver.findElementByLinkText("Add Defect Tracker").click();
		 * wait.until
		 * (ExpectedConditions.visibilityOfElementLocated(By.id("addDTForm")));
		 * //TODO missing id
		 * driver.findElementByLinkText("Add Defect Tracker").click();
		 * wait.until(ExpectedConditions.visibilityOfElementLocated(By.id(
		 * "createDefectTracker")));
		 * driver.findElementById("nameInput").sendKeys(defectTrackerName);
		 * driver.findElementById("urlInput").sendKeys(defectTrackerURL); new
		 * Select
		 * (driver.findElementById("defectTrackerTypeSelect")).selectByVisibleText
		 * (defectTrackerType); driver.findElementById("submitDTModal").click();
		 * wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id(
		 * "createDefectTracker"))); //TODO currently does not allow you to add
		 * a defect tracker from application detail page return new
		 * ApplicationDetailPage(driver);
		 */
	}

	public ApplicationDetailPage addDefectTracker(String defectTracker,
			String username, String password, String productname) {
			clickEditDeleteBtn()
				.clickAddDefectTrackerButton()
				.selectDefectTracker(defectTracker)
				.setUsername(username)
				.setPassword(password)
				.clickTestConnection()
				.selectProduct(productname)
				.clickSubmitTrackerButton();
//		    waitForElement(driver.findElementById("defectTrackerText"));
			sleep(1000);
		    return new ApplicationDetailPage(driver);
		/*
		 * wait.until(ExpectedConditions.visibilityOfElementLocated(By
		 * .id("appInfoDiv"))); // TODO missing id
		 * driver.findElementByLinkText("Add Defect Tracker").click();
		 * wait.until(ExpectedConditions.visibilityOfElementLocated(By
		 * .id("addDTForm"))); new
		 * Select(driver.findElementById("defectTrackerId"))
		 * .selectByVisibleText(defectTracker);
		 * driver.findElementById("username").sendKeys(username);
		 * driver.findElementById("password").sendKeys(password);
		 * driver.findElementByLinkText("Test Connection").click();
		 * wait.until(ExpectedConditions.visibilityOfElementLocated(By
		 * .id("jsonResult"))); new
		 * Select(driver.findElementById("projectList"))
		 * .selectByVisibleText(productname);
		 * driver.findElementById("submitDTModal").click();
		 * wait.until(ExpectedConditions.invisibilityOfElementLocated(By
		 * .id("addDTForm"))); return new ApplicationDetailPage(driver);
		 */
	}
	
	public ApplicationDetailPage editDefectTracker(String defectTracker,
			String username, String password, String productname) {
		clickEditDeleteBtn()
			.clickEditDefectTrackerButton()
			.selectDefectTracker(defectTracker)
			.setUsername(username)
			.setPassword(password)
			.clickTestConnection()
			.selectProduct(productname)
			.clickSubmitTrackerButton();
//		waitForElement(driver.findElementById("defectTrackerText"));
		sleep(1000);
		return new ApplicationDetailPage(driver);
		/*
		 * wait.until(ExpectedConditions.visibilityOfElementLocated(By
		 * .id("appInfoDiv"))); // TODO missing id
		 * driver.findElementByLinkText("Add Defect Tracker").click();
		 * wait.until(ExpectedConditions.visibilityOfElementLocated(By
		 * .id("addDTForm"))); new
		 * Select(driver.findElementById("defectTrackerId"))
		 * .selectByVisibleText(defectTracker);
		 * driver.findElementById("username").sendKeys(username);
		 * driver.findElementById("password").sendKeys(password);
		 * driver.findElementByLinkText("Test Connection").click();
		 * wait.until(ExpectedConditions.visibilityOfElementLocated(By
		 * .id("jsonResult"))); new
		 * Select(driver.findElementById("projectList"))
		 * .selectByVisibleText(productname);
		 * driver.findElementById("submitDTModal").click();
		 * wait.until(ExpectedConditions.invisibilityOfElementLocated(By
		 * .id("addDTForm"))); return new ApplicationDetailPage(driver);
		 */
	}

	public ApplicationDetailPage addNewWaf(String Name, String Type) {
		clickShowDetails();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By
				.id("appInfoDiv")));
		// TODO should be switched to id
		driver.findElementByLinkText("Add WAF").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By
				.id("addWafForm")));
		driver.findElementByLinkText("Create New WAF").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By
				.id("createWaf")));
		driver.findElementById("nameInput").sendKeys(Name);
		new Select(driver.findElementById("typeSelect"))
				.selectByVisibleText(Type);
		driver.findElementById("submitTeamModal").click();
		// TODO currently does not allow you to add a waf from application
		// detail page
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage addWaf(String wafName) {
		Select s = new Select(driver.findElementById("wafSelect"));
		s.selectByVisibleText(wafName);
		driver.findElementById("submitTeamModal").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickEditDeleteBtn() {
		driver.findElementById("editApplicationModalButton").click();
		waitForElement(driver.findElementById("editApplicationModal"));
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage addManualFinding(Boolean stat, String cwe,
			String url, String sourceFile, String lineNum, String Parameter,
			String Severity, String description) {
		driver.findElementById("addManualFindinModalLink").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By
				.id("addManualFinding")));
		if (stat) {
			driver.findElementById("staticRadioButton").click();
		}
		driver.findElementById("txtSearch").sendKeys(cwe);
		driver.findElementById("urlDynamicSearch").sendKeys(url);
		driver.findElementById("urlStaticSearch").sendKeys(sourceFile);
		driver.findElementById("urlSearch").sendKeys(lineNum);
		driver.findElementById("parameterInput").sendKeys(Parameter);
		new Select(driver.findElementById("severityInput"))
				.selectByVisibleText(Severity);
		driver.findElementById("descriptionInput").sendKeys(description);
		driver.findElementById("submitDTModal").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By
				.id("addManualFinding")));
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

	public String getWafText() {
		waitForElement(driver.findElementById("wafText"));
		return driver.findElementById("wafText").getText();
	}

	public String getNameText() {
		return driver.findElementById("nameText").getText();
	}

	public String getUrlText() {
		return driver.findElementById("urlText").getText().trim();
	}

	public String getDefectTrackerText() {
		return driver.findElementById("defectTrackerText").getText().trim();
	}

	/*
	 * public String getOrganizationText(){ return
	 * driver.findElementById("organizationText").getText(); }
	 */

//	public ApplicationDetailPage clickEditLink() {
//		clickEditDeleteBtn();
//		driver.findElementById("editApplicationModalButton").click();
//		waitForElement(driver.findElementById("editAppForm"));
//		return new ApplicationDetailPage(driver);
//	}

	public TeamDetailPage clickTeamLink() {
		driver.findElementById("organizationText").click();
		sleep(300);
		return new TeamDetailPage(driver);
	}

	public TeamDetailPage clickDeleteLink() {
		clickEditDeleteBtn();
		sleep(1000);
		driver.findElementById("deleteLink").click();
		handleAlert();

		return new TeamDetailPage(driver);
	}

	public ApplicationDetailPage clickDetailsLink() {
		clickEditDeleteBtn();
		driver.findElementById("showDetailsLink").click();
		waitForElement(driver.findElementById("appInfoDiv"));
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickScansTab() {
		sleep(1000);
		driver.findElementById("scanTabLink").click();
		waitForElement(driver.findElementById("channelType1"));
		return new ApplicationDetailPage(driver);
	}


	public ManualUploadPage clickAddFindingManuallyLink() {
		driver.findElementById("addFindingManuallyLink").click();
		return new ManualUploadPage(driver);
	}
	
	public ApplicationDetailPage clickCloseManualFindingButton() {
		driver.findElementById("closeManualFindingModalButton").click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By
				.id("closeManualFindingModalButton")));
		return new ApplicationDetailPage(driver);
	}

	public boolean getVulnCount(int cnt) {
		int i = 0;
		if(!driver.findElementById("vulnTabLink").getText().contains(Integer.toString(cnt))){
			System.out.println("tab");
			return false;
		}
		i+=driver.findElementsByClassName("expandable").size();
		if(i!=cnt && cnt<=100){
			return false;
		}
		
		return true;
	}
	
	public ApplicationDetailPage clickVulnTab(){
		driver.findElementById("vulnTabLink").click();
		sleep(1000);
		waitForElement(driver.findElementById("expandAllVulns"));
		return new ApplicationDetailPage(driver);
	}
	

//	public ApplicationDetailPage waitForScans() {
//
//		ApplicationDetailPage returnPage = this;
//
//		String appName = getNameText();
//
//		returnPage = returnPage.clickTeamLink()
//				.clickTextLinkInApplicationsTableBody(appName);
//
//		while (!isElementPresent("ajaxVulnTable")) {
//			returnPage = returnPage.clickTeamLink()
//					.clickTextLinkInApplicationsTableBody(appName);
//			sleep(2000);
//		}
//		return returnPage;
//	}

	public ApplicationDetailPage clickEditWaf() {
		driver.findElementById("editWafButton").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By
				.id("addWaf")));
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickAddWaf() {
		driver.findElementById("addWafButton").click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By
				.id("addWafForm")));
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage setNameInput(String appName2) {
		driver.findElementById("nameInput").clear();
		driver.findElementById("nameInput").sendKeys(appName2);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage setUrlInput(String url) {
		driver.findElementById("urlInput").clear();
		driver.findElementById("urlInput").sendKeys(url);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage setAppCritic(String critic) {
		new Select(driver.findElementById("criticalityId"))
				.selectByVisibleText(critic);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickUpdateApplicationButton() {
		driver.findElementById("submitAppModal").click();
		try {
			waitForInvisibleElement(driver.findElementById("editApplicationModal"));
		}catch(TimeoutException e){
			driver.findElementById("submitAppModal").click();
			waitForInvisibleElement(driver.findElementById("editApplicationModal"));
		}catch(StaleElementReferenceException e){
			
		}
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickUpdateApplicationButtonInvalid() {
		sleep(1000);
		driver.findElementById("submitAppModal").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}

	public String getNameError() {
		return driver.findElementById("name.errors").getText().trim();
	}

	public String getUrlError() {
		return driver.findElementById("url.errors").getText().trim();
	}

	public boolean isDefectTrackerAttached() {
		if (driver.findElementById("defectTrackerText").isEnabled())
			return true;
		return false;
	}

	public ApplicationDetailPage clickDeleteScanButton(int i) {
		driver.findElementsByClassName("scanDelete").get(i).click();
		handleAlert();
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage setFileInput(String file) {
		driver.findElementById("fileInput"+modalNumber()).sendKeys(file);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage submitScan(){
		int scanCnt = scanCount();
		int timer = 0;
		driver.findElementById("submitScanModal"+modalNumber()).click();
//		waitForInvisibleElement(driver.findElementById("scanForm"+modalNumber()));
		sleep(2000);
		waitForScanUpload(0);
//		waitForElement(driver.findElementById("scanTabLink"));
		while(scanCnt != scanCnt+1){
			scanCnt = scanCount();
			sleep(100);
			if(timer>=100){
				break;
			}
			timer++;
			
		}
		return new ApplicationDetailPage(driver);
	}
	
	public void waitForScanUpload(int timer){
		if(timer == 20){
			throw new NoSuchElementException("Unable to locate element: {\"method\":\"id\",\"selector\":\"scanTabLink\"}");
		}
		try{
			driver.findElementById("scanTabLink");
		}catch(NoSuchElementException e){
			sleep(1000);
			waitForScanUpload(timer+1);
		}
		
	}
	
	public int scanCount(){
		WebElement scanTab;
		try{
			scanTab = driver.findElementById("scanTabLink");
		}catch(NoSuchElementException e){
			return 0;
		}
		
		String scanText = scanTab.getText().trim();
		Pattern pattern = Pattern.compile("^\\s*(\\d+)");
		Matcher matcher = pattern.matcher(scanText);
		if(matcher.find()){
			return Integer.parseInt(matcher.group(1));
		}
		return -1;
	}
	
	public boolean isScanChannelPresent(String channel){
		int rowCnt = driver.findElementsByClassName("bodyRow").size();
		for(int i = 1; i <= rowCnt; i++){
			if(driver.findElementById("channelType"+i).getText().trim().equals(channel)){
				return true;
			}
		}
		return false;
	}
	
	public ApplicationDetailPage submitScanInvalid(){
		driver.findElementById("submitScanModal"+modalNumber()).click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public int modalNumber(){
		String s = driver.findElementByClassName("modal").getAttribute("id");
		Pattern pattern = Pattern.compile("^\\D+([0-9]+)$");
		Matcher matcher = pattern.matcher(s);
		if(matcher.find()){
			return  Integer.parseInt(matcher.group(1));
		}
		return -1;
	}
	
	public boolean isDuplicateScan(){
		sleep(1000);
		String s = "";
		for(int i=0;i<10;i++){
			try{
				s = driver.findElementByClassName("in").findElements(By.className("alert-error")).get(1).getText();
			}catch(IndexOutOfBoundsException e){
				sleep(500);
				continue;
			}
			break;
		}
		return s.contains("Scan file has already been uploaded.");
	}
	

	public ApplicationDetailPage clickUploadScanLink() {
		driver.findElementById("uploadScanModalLink").click();
		waitForElement(driver.findElementById("uploadScan"+modalNumber()));
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickCloseScanUploadModal(){
		driver.findElementById("closeScanModalButton").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage fillAllClickSaveDynamic(Boolean dynamicRadioButton, String cwe, String url, 
			String param, String severity, String description) {
		fillRequiredManual(cwe, url, param, severity,description);
		clickDynamicSubmit();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage fillRequiredManual(String cwe, String url, String param, String severity, String description) {
		setCWE(cwe);
		setURL(url);
		setParameter(param);
		selectSeverityList(severity);
		setDescription(description);
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickDynamicSubmit() {
		driver.findElementById("dynamicSubmit").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	
	public ApplicationDetailPage clickStaticSubmit() {
		driver.findElementById("staticSubmit").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickDynamicSubmitInvalid() {
		driver.findElementById("dynamicSubmit").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage setCWE(String Status) {
		driver.findElementById("txtSearch").clear();
		driver.findElementById("txtSearch").sendKeys(Status);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage setURL(String Status) {
		driver.findElementById("urlDynamicSearch").clear();
		driver.findElementById("urlDynamicSearch").sendKeys(Status);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage setParameter(String Status) {
		driver.findElementById("parameterInput").clear();
		driver.findElementById("parameterInput").sendKeys(Status);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage setDescription(String Status) {
		driver.findElementById("descriptionInput").clear();
		driver.findElementById("descriptionInput").sendKeys(Status);
		return new ApplicationDetailPage(driver);
	}
	
	public String selectSeverityList(String text) {
		Select severity = new Select(driver.findElementById("severityInput"));
		severity.selectByVisibleText(text);
		return severity.getFirstSelectedOption().getText();
	}
	
	public ApplicationDetailPage clickExpandAllVulns(){
		driver.findElementById("expandAllVulns").click();
		sleep(3000);
//		waitForElement(driver.findElementById("vulnName1"));
		return new ApplicationDetailPage(driver);
	}
	
	public boolean isScanPresent(String scan){
		return driver.findElementById("wafTableBody").getText().contains(scan);
	}
	
	public boolean isScanCountCorrect(int cnt){
		return driver.findElementById("scanTabLink").getText().contains(Integer.toString(cnt));
	}

    public ApplicationDetailPage clickScansQueueTab() {
        driver.findElementById("scanQueueTabLink").click();
        sleep(1000);
        waitForElement(driver.findElementById("scanQueueTable"));
        return new ApplicationDetailPage(driver);
    }

    public int scanQueueCount(){
        WebElement scanQueueTab;
        try{
            scanQueueTab = driver.findElementById("scanQueueTabLink");
        }catch(NoSuchElementException e){
            return 0;
        }

        String scanText = scanQueueTab.getText().trim();
        Pattern pattern = Pattern.compile("^\\s*(\\d+)");
        Matcher matcher = pattern.matcher(scanText);
        if(matcher.find()){
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    public ApplicationDetailPage clickAddNewScanQueueLink() {
        driver.findElementById("addScanQueueLink"+modalNumber()).click();
        waitForElement(driver.findElementById("addScanQueue"+modalNumber()));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setDocFileInput(String file) {
        driver.findElementById("docInput"+modalNumber()).sendKeys(file);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage submitScanQueue() {
        driver.findElementById("addScanQueueButton"+modalNumber()).click();
        sleep(1000);
        return new ApplicationDetailPage(driver);
    }

    public boolean isScanQueuePresent(String scanner){
        int rowCnt = driver.findElementsByClassName("bodyRow").size();
        for(int i = 1; i <= rowCnt; i++){
            if(driver.findElementById("scannerType"+i).getText().trim().equals(scanner)){
                return true;
            }
        }
        return false;
    }

    public ApplicationDetailPage clickDocumentTab() {
        driver.findElementById("docsTabLink").click();
        sleep(1000);
        waitForElement(driver.findElementById("uploadDocModalLink"+modalNumber()));
        return new ApplicationDetailPage(driver);
    }

    public int docsCount(){
        WebElement scanQueueTab;
        try{
            scanQueueTab = driver.findElementById("docsTabLink");
        }catch(NoSuchElementException e){
            return 0;
        }

        String scanText = scanQueueTab.getText().trim();
        Pattern pattern = Pattern.compile("^\\s*(\\d+)");
        Matcher matcher = pattern.matcher(scanText);
        if(matcher.find()){
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    public ApplicationDetailPage clickUploadDocLink() {
        driver.findElementById("uploadDocModalLink"+modalNumber()).click();
        waitForElement(driver.findElementById("uploadDoc"+modalNumber()));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setScanQueueType(String scanQueueType) {
        new Select(driver.findElementById("scanQueueType"))
                .selectByVisibleText(scanQueueType);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage submitDoc() {
        driver.findElementById("submitDocModal"+modalNumber()).click();
        sleep(3000);
        return new ApplicationDetailPage(driver);
    }

    public boolean isDocPresent(String docName){
        int rowCnt = driver.findElementsByClassName("bodyRow").size();
        for(int i = 1; i <= rowCnt; i++){
            if(driver.findElementById("docName"+i).getText().trim().equals(docName)){
                return true;
            }
        }
        return false;
    }
}
