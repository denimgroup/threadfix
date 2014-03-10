////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
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
        sleep(1000);
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
        sleep(2000);
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
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage selectProduct(String product) {
        sleep(4000);
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
        sleep(4000);
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
        waitForElement(driver.findElementById("addDefectTrackerSuccessMessage"));
        sleep(5000);
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

    public ApplicationDetailPage clickActionButton() {
        waitForElement(driver.findElementById("actionButton"));
        driver.findElementById("actionButton").click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickViewPermUsers() {
        clickActionButton();
        driver.findElementById("userListModelButton").click();
        waitForElement(driver.findElementById("usersModal"));
        return new ApplicationDetailPage(driver);
    }

    public int getNumPermUsers() {
        return driver.findElementById("userTableBody").findElements(By.className("bodyRow")).size();
    }

    public ApplicationDetailPage clickEditDeleteBtn() {
        clickActionButton();
        driver.findElementById("editApplicationModalButton").click();
        waitForElement(driver.findElementById("editApplicationModal"));
        return new ApplicationDetailPage(driver);
    }

    public int getNameWidth() {
        return driver.findElementById("nameText").getSize().getWidth();
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
        return driver.findElementById("urlInput").getAttribute("value");
    }

    public String getDefectTrackerText() {
        return driver.findElementById("defectTrackerText").getText().trim();
    }

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


    public ApplicationDetailPage clickVulnTab() {
        driver.findElementById("vulnTabLink").click();
        sleep(1000);
        waitForElement(driver.findElementById("expandAllVulns"));
        return new ApplicationDetailPage(driver);
    }

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
        } catch (TimeoutException e) {
            driver.findElementById("submitAppModal").click();
            waitForInvisibleElement(driver.findElementById("editApplicationModal"));
        } catch (StaleElementReferenceException e) {
            e.printStackTrace();
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

    public ApplicationDetailPage clickDeleteScanButton(int i) {
        driver.findElementsByClassName("scanDelete").get(i).click();
        handleAlert();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setFileInput(String appName, String file) {
        driver.findElementById("fileInput-" + appName).sendKeys(file);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage submitScan(String appName) {
        driver.findElementById("submitScanModal-" + appName).click();
        waitForScanUpload(0);
        sleep(15000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage submitDefect() {
        driver.findElementById("submitDefectForm").findElement(By.id("submitScanModal")).click();
        sleep(1000);
        waitForInvisibleElement(driver.findElementById("submitDefectForm"));
        sleep(3000);
        return new ApplicationDetailPage(driver);
    }

    @Deprecated
    public void waitForScanUpload(int timer) {
        if (timer == 20) {
            throw new NoSuchElementException("Unable to locate element: {\"method\":\"id\",\"selector\":\"scanTabLink\"}");
        }
        try {
            driver.findElementById("scanTabLink");
        } catch (NoSuchElementException e) {
            sleep(1000);
            waitForScanUpload(timer + 1);
        }
    }

    public int scanCount() {
        WebElement scanTab;
        try {
//			scanTab = driver.findElementById("scanTabLink");
            driver.findElementById("scanTabLink").isDisplayed();
        } catch (NoSuchElementException e) {
            return 0;
        }

//		String scanText = scanTab.getText().trim();
        String scanText = driver.findElementById("scanTabLink").getText().trim();
        Pattern pattern = Pattern.compile("^\\s*(\\d+)");
        Matcher matcher = pattern.matcher(scanText);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    public ApplicationDetailPage submitScanInvalid() {
        driver.findElementById("submitScanModal" + modalNumber()).click();
        sleep(1000);
        return new ApplicationDetailPage(driver);
    }

    public int modalNumber() {
        String s = driver.findElementByClassName("modal").getAttribute("id");
        Pattern pattern = Pattern.compile("^\\D+([0-9]+)$");
        Matcher matcher = pattern.matcher(s);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    public String getAlert() {
        return driver.findElementByClassName("alert-success").getText();
    }

    public ApplicationDetailPage clickUploadScanLink() {
        clickActionButton();
        driver.findElementById("uploadScanModalLink").click();
        sleep(4000);
        waitForElement(driver.findElementById("uploadScan" + modalNumber()));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickCloseScanUploadModal() {
        driver.findElementById("closeScanModalButton").click();
        sleep(1000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage fillAllClickSaveDynamic(Boolean dynamicRadioButton, String cwe, String url,
                                                         String param, String severity, String description) {
        fillRequiredManual(cwe, url, param, severity, description);
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

    public ApplicationDetailPage clickExpandAllVulns() {
        sleep(15000); //sleep is required for javascript to load
        wait.until(ExpectedConditions.elementToBeClickable(By.id("expandAllVulns")));
        driver.findElementById("expandAllVulns").click();
        waitForElement(driver.findElementById("vulnName1"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickVulnCheckBox(int num) {
        driver.findElementsByClassName("vulnIdCheckbox").get(num).click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickCloseAppModal() {
        driver.findElementById("editAppFormDiv").findElement(By.className("modal-footer")).findElements(By.className("btn")).get(0).click();
        sleep(2500);
        return new ApplicationDetailPage(driver);
    }

    public int getNumOfSubmitedDefects() {
        return driver.findElementById("anyid").findElements(By.className("transparent_png")).size();
    }

    public ApplicationDetailPage clickDefectActionBtn() {
        wait.until(ExpectedConditions.elementToBeClickable(By.id("actionButton1")));
        driver.findElementsById("actionButton1").get(1).click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickSubmitDefectLink() {
        clickDefectActionBtn();
        driver.findElementById("submitDefectButton").click();
        sleep(2000);
        waitForElement(driver.findElementById("submitDefectForm"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickMergeDefectLink() {
        clickDefectActionBtn();
        driver.findElementById("mergeDefectButton").click();
        sleep(3000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage selectMergeDefect(String defect) {
        sleep(20000);
        new Select(driver.findElementById("defectId")).selectByVisibleText(defect);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickMergeDefectSubmit() {
        driver.findElementsById("mergeDefectButton").get(2).click();
        sleep(4000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickMarkClosedLink() {
        clickDefectActionBtn();
        driver.findElementById("markClosedButton").click();
        sleep(1000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickMarkFalsePositiveLink() {
        clickDefectActionBtn();
        driver.findElementById("markFalsePositiveButton").click();
        sleep(1000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addCommentToFirstVuln(String comment) {
        clickExpandAllVulns();
        expandFirstVuln();
        driver.findElementsByLinkText("Add Comment").get(0).click();
        sleep(1000);
        driver.findElementsById("commentInputBox").get(0).clear();
        driver.findElementsById("commentInputBox").get(0).sendKeys(comment);
        for (int i = 0; i < driver.findElementsByClassName("modal").size(); i++) {
            if (driver.findElementsByClassName("modal").get(i).getAttribute("id").contains("commentModal")) {
                driver.findElementsByClassName("modal").get(i).findElement(By.linkText("Add Comment")).click();
            }
        }
        sleep(3000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandFirstVuln() {
        driver.findElementsByClassName("expandableTrigger").get(1).click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickScansQueueTab() {
        driver.findElementById("scanQueueTabLink").click();
        sleep(1000);
        waitForElement(driver.findElementById("scanQueueTable"));
        return new ApplicationDetailPage(driver);
    }

    public int scanQueueCount() {
        WebElement scanQueueTab;
        try {
            scanQueueTab = driver.findElementById("scanQueueTabLink");
        } catch (NoSuchElementException e) {
            return 0;
        }

        String scanText = scanQueueTab.getText().trim();
        Pattern pattern = Pattern.compile("^\\s*(\\d+)");
        Matcher matcher = pattern.matcher(scanText);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    public ApplicationDetailPage clickAddNewScanQueueLink() {
        driver.findElementById("addScanQueueLink" + modalNumber()).click();
        waitForElement(driver.findElementById("addScanQueue" + modalNumber()));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setDocFileInput(String file) {
        driver.findElementById("docInput" + modalNumber()).sendKeys(file);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage submitScanQueue() {
        driver.findElementById("addScanQueueButton" + modalNumber()).click();
        sleep(1000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickDocumentTab() {
        driver.findElementById("docsTabLink").click();
        sleep(1000);
        waitForElement(driver.findElementById("uploadDocModalLink" + modalNumber()));
        return new ApplicationDetailPage(driver);
    }

    public int docsCount() {
        WebElement scanQueueTab;
        try {
            scanQueueTab = driver.findElementById("docsTabLink");
        } catch (NoSuchElementException e) {
            return 0;
        }

        String scanText = scanQueueTab.getText().trim();
        Pattern pattern = Pattern.compile("^\\s*(\\d+)");
        Matcher matcher = pattern.matcher(scanText);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    public ApplicationDetailPage clickUploadDocLink() {
        driver.findElementById("uploadDocModalLink" + modalNumber()).click();
        waitForElement(driver.findElementById("uploadDoc" + modalNumber()));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setScanQueueType(String scanQueueType) {
        new Select(driver.findElementById("scanQueueType"))
                .selectByVisibleText(scanQueueType);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage submitDoc() {
        driver.findElementById("submitDocModal" + modalNumber()).click();
        sleep(3000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setTeam(String team) {
        new Select(driver.findElementById("organizationId")).selectByVisibleText(team);
        return new ApplicationDetailPage(driver);
    }

    public String specificVulnerabilityCount(String level) {
        List<WebElement> headers = driver.findElementsByClassName("vulnSectionHeader");

        for (WebElement header : headers) {
            if (header.getText().contains(level)) {
                String count = header.getText();
                count = count.substring(count.length() - 2, count.length() - 1);
                return count;
            }
        }

        return "0";
    }

    public FilterPage clickEditVulnerabilityFilters() {
        driver.findElementById("editVulnerabilityFiltersButton").click();
        return new FilterPage(driver);
    }

    public ApplicationDetailPage clickManualFindingButton() {
        driver.findElementById("addManualFindingModalLink").click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickStaticRadioButton() {
        driver.findElementById("staticRadioButton").click();
        return new ApplicationDetailPage(driver);
    }

    /*________________ Boolean Functions ________________*/

    public boolean isApplicationNamePresent() {
        return driver.findElementById("nameText").isDisplayed();
    }

    public boolean isBreadcrumbPresent() {
        return driver.findElementByLinkText("Applications Index").isDisplayed();
    }

    public boolean isApplicationBreadcrumbPresent(String applicationName) {
        return driver.findElementByLinkText("Team: " + applicationName).isDisplayed();
    }

    public boolean isDocPresent(String docName) {
        int rowCnt = driver.findElementsByClassName("bodyRow").size();
        for (int i = 1; i <= rowCnt; i++) {
            if (driver.findElementById("docName" + i).getText().trim().equals(docName)) {
                return true;
            }
        }
        return false;
    }

    public boolean vulnerabilitiesFiltered(String level, String expected) {
        return specificVulnerabilityCount(level).equals(expected);
    }

    public boolean isScanQueuePresent(String scanner) {
        int rowCnt = driver.findElementsByClassName("bodyRow").size();
        for (int i = 1; i <= rowCnt; i++) {
            if (driver.findElementById("scannerType" + i).getText().trim().equals(scanner)) {
                return true;
            }
        }
        return false;
    }

    public boolean isUserPresentPerm(String user) {
        for (int i = 1; i <= getNumPermUsers(); i++) {
            if (driver.findElementById("name" + i).getText().contains(user)) {
                return true;
            }
        }
        return false;
    }

    public boolean getVulnCount(int cnt) {
        int i = 0;
        if (!driver.findElementById("vulnTabLink").getText().contains(Integer.toString(cnt))) {
            System.out.println("tab");
            return false;
        }
        i += driver.findElementsByClassName("expandable").size();
        if (i != cnt && cnt <= 100) {
            return false;
        }

        return true;
    }

    public boolean isScanPresent(String scan) {
        return driver.findElementById("wafTableBody").getText().contains(scan);
    }

    public boolean isScanCountCorrect(int cnt) {
        return driver.findElementById("scanTabLink").getText().contains(Integer.toString(cnt));
    }

    public boolean isDuplicateScan() {
        sleep(1000);
        String s = "";
        for (int i = 0; i < 10; i++) {
            try {
                s = driver.findElementByClassName("in").findElements(By.className("alert-error")).get(1).getText();
            } catch (IndexOutOfBoundsException e) {
                sleep(500);
                continue;
            }
            break;
        }
        return s.contains("Scan file has already been uploaded.");
    }

    public boolean isDefectTrackerAttached() {
        if (driver.findElementById("defectTrackerText").isEnabled())
            return true;
        return false;
    }

    public boolean isScanChannelPresent(String channel) {
        int rowCnt = driver.findElementsByClassName("bodyRow").size();
        for (int i = 1; i <= rowCnt; i++) {
            if (driver.findElementById("channelType" + i).getText().trim().equals(channel)) {
                return true;
            }
        }
        return false;
    }

    public boolean isActionButtonPresent() {
        return driver.findElementById("actionButton").isDisplayed();
    }

    public boolean isActionButtonClickable() {
        return isClickable("actionButton");
    }

    public boolean isEditDeletePresent() {
        return driver.findElementById("editApplicationModalButton").isDisplayed();
    }

    public boolean isEditDeleteClickable() {
        return isClickable("editApplicationModalButton");
    }

    public boolean isEditVulnFiltersPresent() {
        return driver.findElementById("editVulnerabilityFiltersButton").isDisplayed();
    }

    public boolean isEditVulnFiltersClickable() {
        return isClickable("editVulnerabilityFiltersButton");
    }

    public boolean isUploadScanPresent() {
        return driver.findElementById("uploadScanModalLink").isDisplayed();
    }

    public boolean isUploadScanClickable() {
        return isClickable("uploadScanModalLink");
    }

    public boolean isAddManualFindingsPresent() {
        return driver.findElementById("addManualFindingModalLink").isDisplayed();
    }

    public boolean isAddManualFindingsClickable() {
        return isClickable("addManualFindingModalLink");
    }

    public boolean isDeleteButtonPresent() {
        return driver.findElementById("deleteLink").isDisplayed();
    }

    public boolean isDeletebuttonClickable() {
        return isClickable("deleteLink");
    }

    public boolean isNameInputPresent() {
        return driver.findElementById("nameInput").isDisplayed();
    }

    public boolean isURLInputPresent() {
        return driver.findElementById("urlInput").isDisplayed();
    }

    public boolean isUniqueIDPresent() {
        return driver.findElementById("uniqueIdInput").isDisplayed();
    }

    public boolean isTeamSelectionPresent() {
        return driver.findElementById("organizationId").isDisplayed();
    }

    public boolean isCritcalityPresent() {
        return driver.findElementById("criticalityId").isDisplayed();
    }

    public boolean isAppTypePresent() {
        return driver.findElementById("frameworkType").isDisplayed();
    }

    public boolean isSourceURLPresent() {
        return driver.findElementById("repositoryUrl").isDisplayed();
    }

    public boolean isSourceFolderPresent() {
        return driver.findElementById("repositoryFolder").isDisplayed();
    }

    public boolean isDefectTrackerAddPresent() {
        return driver.findElementById("addDefectTrackerButton").isDisplayed();
    }

    public boolean isDefectTrackerAddClickable() {
        return isClickable("addDefectTrackerButton");
    }

    public boolean isWAFAddButtonPresent() {
        return driver.findElementById("addWafButton").isDisplayed();
    }

    public boolean isWAFAddButtonClickable() {
        return isClickable("addWafButton");
    }

    public boolean isSaveChangesButtonPresent() {
        return driver.findElementById("submitAppModal").isDisplayed();
    }

    public boolean isSaveChangesButtonClickable() {
        return isClickable("submitAppModal");
    }

    public boolean isSubmitScanLinkPresent(String appName) {
        return driver.findElementById("submitScanModal-" + appName).isDisplayed();
    }

    public boolean isDynamicRadioPresent() {
        return driver.findElementById("dynamicRadioButton").isDisplayed();
    }

    public boolean isStaticRadioPresent() {
        return driver.findElementById("staticRadioButton").isDisplayed();
    }

    public boolean isCWEInputPresent() {
        return driver.findElementById("txtSearch").isDisplayed();
    }

    public boolean isURLDynamicSearchPresent() {
        return driver.findElementById("urlDynamicSearch").isDisplayed();
    }

    public boolean isURLStaticSearchPresent() {
        return driver.findElementById("urlStaticSearch").isDisplayed();
    }

    public boolean isLineNumberInputPresent() {
        return driver.findElementById("urlSearch").isDisplayed();
    }

    public boolean isParameterPresent() {
        return driver.findElementById("parameterInput").isDisplayed();
    }

    public boolean isSeverityPresent() {
        return driver.findElementById("severityInput").isDisplayed();
    }

    public boolean isDescriptionInputPresent() {
        return driver.findElementById("descriptionInput").isDisplayed();
    }

    public boolean isSubmitManualFindingPresent() {
        return driver.findElementById("dynamicSubmit").isDisplayed();
    }

    public boolean isSubmitManualFindingClickable() {
        return isClickable("dynamicSubmit");
    }

    public boolean isManualFindingCloseButtonPresent() {
        return driver.findElementById("closeManualFindingModalButton").isDisplayed();
    }

    public boolean isManualFindingCloseButtonClickable() {
        return isClickable("closeManualFindingModalButton");
    }

}
