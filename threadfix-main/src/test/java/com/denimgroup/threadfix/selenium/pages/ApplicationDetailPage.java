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


import org.openqa.selenium.*;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApplicationDetailPage extends BasePage {

    WebDriverWait wait = new WebDriverWait(driver, 10);

    public ApplicationDetailPage(WebDriver webdriver) {
        super(webdriver);
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
        waitForElement(driver.findElementById("getProductNames"));
        driver.findElementById("getProductNames").click();
        sleep(5000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage selectProduct(String product) {
        sleep(4000);
        new Select(driver.findElementById("productNameSelect"))
                .selectByVisibleText(product);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage selectDefectTracker(String defectTracker) {
        waitForElement(driver.findElementById("defectTrackerId"));
        new Select(driver.findElementById("defectTrackerId"))
                .selectByVisibleText(defectTracker);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addDefectTracker(String defectTracker, String username,
                                                  String password, String productName) {
        clickEditDeleteBtn()
                .clickAddDefectTrackerButton()
                .selectDefectTracker(defectTracker)
                .setUsername(username)
                .setPassword(password)
                .clickTestConnection()
                .selectProduct(productName)
                .clickUpdateApplicationButton()
                .clickUpdateApplicationButton();

        sleep(2000);

        return new ApplicationDetailPage(driver);

    }

    public ApplicationDetailPage addWaf(String wafName) {
        Select s = new Select(driver.findElementById("wafSelect"));
        s.selectByVisibleText(wafName);
        sleep(4000);
        return this;
    }

    public ApplicationDetailPage saveWafAdd() {
        driver.findElementById("submit").click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickActionButton() {
        waitForElement(driver.findElementById("actionButton1"));
        sleep(3000);
        driver.findElementById("actionButton1").click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickViewPermUsers() {
        clickActionButton();
        driver.findElementById("userListModelButton").click();
        waitForElement(driver.findElementById("myModalLabel"));
        return new ApplicationDetailPage(driver);
    }

    public int getNumPermUsers() {
        return driver.findElementById("userTableBody").findElements(By.className("bodyRow")).size();
    }

    public ApplicationDetailPage clickEditDeleteBtn() {
        sleep(2000);
        clickActionButton();
        sleep(2000);
        waitForElement(driver.findElementById("editApplicationModalButton"));
        driver.findElementById("editApplicationModalButton").click();
        waitForElement(driver.findElementById("deleteLink"));
        return new ApplicationDetailPage(driver);
    }

    public TeamDetailPage clickDeleteLink() {
        driver.findElementById("deleteLink").click();
        handleAlert();
        return new TeamDetailPage(driver);
    }

    public String getWafText() {
        waitForElement(driver.findElementById("wafName"));
        return driver.findElementById("wafName").getText();
    }

    public String getNameText() {
        return driver.findElementById("nameText").getText();
    }

    public String getUrlText() {
        return driver.findElementById("urlInput").getAttribute("value");
    }

    public ApplicationDetailPage clickScansTab() {
        sleep(1000);
        driver.findElementByLinkText("1 Scan").click();
        waitForElement(driver.findElementByLinkText("Delete Scan"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickAddWaf() {
        driver.findElementById("addWafButton").click();
        waitForElement(driver.findElementById("wafSelect"));
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

    public ApplicationDetailPage clickUpdateApplicationButton() {
        sleep(5000);
        driver.findElementById("submit").click();
        sleep(5000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickUpdateApplicationButtonInvalid() {
        sleep(1000);
        driver.findElementById("submit").click();
        sleep(1000);
        return new ApplicationDetailPage(driver);
    }

    public String getNameError() {
        return driver.findElementById("applicationNameInputNameError").getText();
    }

    public String getNameRequiredError() {
        return driver.findElementById("applicationNameInputRequiredError").getText();
    }

    public String getUrlError() {
        return driver.findElementById("applicationUrlInputInvalidUrlError").getText().trim();
    }

    public ApplicationDetailPage clickDeleteScanButton() {
        driver.findElementByLinkText("Delete Scan").click();
        handleAlert();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickDeleteScanTaskButton(String id) {
        driver.findElementById("deleteButton" + id).click();
        handleAlert();
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

    public ApplicationDetailPage clickDynamicSubmit() {
        driver.findElementById("submit").click();
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

    public ApplicationDetailPage clickCloseAppInvalid() {
        driver.findElementByLinkText("Close").click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickScanAgentTasksTab(int count) {
        if (count == 1) {
            driver.findElementByLinkText(count + " Scan Agent Task").click();
        } else {
            driver.findElementByLinkText(count + " Scan Agent Tasks").click();
        }
        sleep(1000);
        waitForElement(driver.findElementById("scanQueueTable"));
        return new ApplicationDetailPage(driver);
    }

    public int scanQueueCount() {
        WebElement scanQueueTab;
        try {
            scanQueueTab = driver.findElementById("scanAgentTasksTab");
        } catch (NoSuchElementException e) {
            return 0;
        }

        String scanText = scanQueueTab.getText().trim();
        Pattern pattern = Pattern.compile("^\\s*(\\d+)");
        Matcher matcher = pattern.matcher(scanText);
        if (matcher.find()) {
            int temp = Integer.parseInt(matcher.group(1));
            return temp;
        }
        return -1;
    }

    public ApplicationDetailPage clickAddNewScanTask() {
        driver.findElementById("addScanQueueLink").click();
        waitForElement(driver.findElementById("submit"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setDocFileInput(String file) {
        driver.findElementById("docFileInput").sendKeys(file);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage submitScanQueue() {
        driver.findElementById("submit").click();
        sleep(1000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickDocumentTab(int count) {
        driver.findElementByLinkText( count + " Files").click();
        waitForElement(driver.findElementByLinkText("Add File"));
        return new ApplicationDetailPage(driver);
    }

    public int docsCount() {
        WebElement scanQueueTab;
        try {
            scanQueueTab = driver.findElementById("documentsTab");
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
        driver.findElementByLinkText("Add File").click();
        waitForElement(driver.findElementById("docFileInput"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setScanQueueType(String scanQueueType) {
        new Select(driver.findElementById("scanner"))
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
        sleep(2000);
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

    public ApplicationDetailPage expandCriticalVulns() {
        driver.findElementById("expandCritical").click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandResultsByLevel(String level) {
        driver.findElementById("expand" + level).click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandVulnerabilityByType(String type) {
        driver.findElementById("expandVuln" + type).click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandCommentSection(String level) {
        driver.findElementById("commentsButton" + level).click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addComment(String level) {
        driver.findElementById("addCommentButton" + level).click();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage setComment(String comment) {
        driver.findElementById("commentInputBox").clear();
        driver.findElementById("commentInputBox").sendKeys(comment);
        return this;
    }

    public boolean vulnsFilteredOpen(int count) {
        return driver.findElementByLinkText( count + " Vulnerabilities").isDisplayed();
    }

    public FilterPage clickEditVulnerabilityFilters() {
        sleep(3000);
        waitForElement(driver.findElementById("editVulnerabilityFiltersButton"));
        driver.findElementById("editVulnerabilityFiltersButton").click();
        return new FilterPage(driver);
    }

    public ApplicationDetailPage clickManualFindingButton() {
        driver.findElementById("addManualFindingModalLink").click();
        waitForElement(driver.findElementById("txtSearch"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickStaticRadioButton() {
        driver.findElementById("staticRadioButton").click();
        return new ApplicationDetailPage(driver);
    }

    public ScanDetailPage clickViewScan() {
        driver.findElementByLinkText("View Scan").click();
        return new ScanDetailPage(driver);
    }

    public ApplicationDetailPage clickSourceInfo(){
        waitForElement(driver.findElementByLinkText("Source Code Information"));
        driver.findElementByLinkText("Source Code Information").click();
        return new ApplicationDetailPage(driver);
    }

    public int getFilterDivHeight() {
        return driver.findElement(By.className("filter-controls")).getSize().getHeight();
    }

    public ApplicationDetailPage toggleAll() {
        driver.findElementById("toggleAllButton").click();
        sleep(2000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleClear() {
        driver.findElementById("clearFiltersButton").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage clickLoadFilters() {
        driver.findElementByLinkText("Load Filters").click();
        waitForElement(driver.findElementById("filterSelect"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandSavedFilters() {
        sleep(2000);
        driver.findElementById("showSaveFilter").click();
        sleep(2000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addSavedFilter(String newFilter) {
        driver.findElementById("filterNameInput").clear();
        driver.findElementById("filterNameInput").sendKeys(newFilter);
        driver.findElementById("saveFilterButton").click();
        waitForElement(driver.findElementById("saveFilterSuccessMessage"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addSavedFilterInvalid(String newFilter) {
        driver.findElementById("filterNameInput").clear();
        driver.findElementById("filterNameInput").sendKeys(newFilter);
        driver.findElementById("saveFilterButton").click();
        waitForElement(driver.findElementById("saveFilterErrorMessage"));
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addInvalidNameSavedFilter(String newFilter) {
        driver.findElementById("filterNameInput").clear();
        driver.findElementById("filterNameInput").sendKeys(newFilter);
        return this;
    }


    public ApplicationDetailPage loadSavedFilter(String savedFilter) {
        new Select(driver.findElementById("filterSelect")).selectByVisibleText(savedFilter);
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandScannerAndMerged() {
        sleep(2000);
        driver.findElementById("expandScannerFilters").click();
        sleep(2000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleTwoPlus() {
        driver.findElementByLinkText("2+").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleThreePlus() {
        driver.findElementByLinkText("3+").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleFourPlus() {
        driver.findElementByLinkText("4+").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleFivePlus() {
        driver.findElementByLinkText("5+").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addScannerFilter(String scanner) {
        driver.findElementById("showScannerInput").click();
        driver.findElementById("scannerTypeahead").sendKeys(scanner);
        driver.findElementById("scannerTypeahead").sendKeys(Keys.RETURN);
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandFieldControls() {
        sleep(2000);
        driver.findElementById("showFieldControls").click();
        sleep(2000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addVulnerabilityTypeFilter(String vulnerabilityType) {
        driver.findElementById("showTypeInput").click();
        driver.findElementById("vulnerabilityTypeTypeahead").sendKeys(vulnerabilityType);
        driver.findElementById("vulnerabilityTypeTypeahead").sendKeys(Keys.RETURN);
        waitForResultsToLoad();
       return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addPathFilter(String path) {
        driver.findElementById("pathInput").sendKeys(path);
        driver.findElementById("pathInput").sendKeys(Keys.RETURN);
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleSeverityFilter(String level) {
        driver.findElementById("show" + level).click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage addParameterFilter(String parameter) {
        driver.findElementById("parameterFilterInput").sendKeys(parameter);
        driver.findElementById("parameterFilterInput").sendKeys(Keys.RETURN);
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleStatusFilter(String status) {
        driver.findElementById("show" + status).click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandAging() {
        sleep(2000);
        driver.findElementById("showDateControls").click();
        sleep(2000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleLessThan() {
        driver.findElementByLinkText("Less Than").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleMoreThan() {
        driver.findElementByLinkText("More Than").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggleOneWeek() {
        driver.findElementByLinkText("1 Week").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggle30Days() {
        driver.findElementByLinkText("30 days").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggle60Days() {
        driver.findElementByLinkText("60 days").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage toggle90Days() {
        driver.findElementByLinkText("90 days").click();
        waitForResultsToLoad();
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage expandDateRange() {
        driver.findElementById("showDateRange").click();
        sleep(2000);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage enterStartDate(String date) {
        driver.findElementById("startDateInput").sendKeys(date);
        return new ApplicationDetailPage(driver);
    }

    public ApplicationDetailPage enterEndDate(String date) {
        driver.findElementById("endDateInput").sendKeys(date);
        return new ApplicationDetailPage(driver);
    }

    public void waitForResultsToLoad() {
        while (driver.findElementById("vulnTreeLoadingSpinner").isDisplayed()) {
            sleep(1000);
        }
    }

    public String getScannerDate(int row) {
        return driver.findElementById("scanAgentTaskCreateTime" + row).getText().trim();
    }

    /*________________ Boolean Functions ________________*/

    public boolean isApplicationNamePresent() {
        return driver.findElementById("nameText").isDisplayed();
    }

    public boolean isBreadcrumbPresent() {
        return driver.findElementById("applicationsIndexLink").isDisplayed();
    }

    public boolean isApplicationBreadcrumbPresent() {
        return driver.findElementById("teamLink").isDisplayed();
    }

    public boolean vulnerabilitiesFiltered(String level, String expected) {
        return specificVulnerabilityCount(level).equals(expected);
    }

    public boolean isScanAgentTaskPresent(String date) {
        int rowCnt = driver.findElementsByClassName("bodyRow").size();
        for (int i = 0; i < rowCnt; i++) {
            try {
                if (driver.findElementById("scanAgentTaskCreateTime" + i).getText().trim().equals(date)) {
                    return true;
                }
            } catch (NoSuchElementException e) {
                System.err.println("Scan Agent Task with date of: " + date + " could not be found. " + e.getMessage());
                return false;
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

    public String remoteProvidersScansUploaded() {
        return driver.findElementByClassName("alert-error").getText();
    }

    public boolean isAppTypeDetect() {
        return driver.findElementById("frameworkType").getText().contains("DETECT");
    }

    public boolean isDefectTrackerAttached() {
        if (driver.findElementById("defectTrackerName").isEnabled())
            return true;
        return false;
    }

    public boolean isActionButtonPresent() {
        return driver.findElementById("actionButton1").isDisplayed();
    }

    public boolean isActionButtonClickable() {
        return isClickable("actionButton1");
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
        return driver.findElementById("repositoryFolderInput").isDisplayed();
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
        return driver.findElementById("lineNumberInput").isDisplayed();
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
        return driver.findElementById("submit").isDisplayed();
    }

    public boolean isSubmitManualFindingClickable() {
        return isClickable("submit");
    }

    public boolean isManualFindingCloseButtonPresent() {
        return driver.findElementById("closeModalButton").isDisplayed();
    }

    public boolean isManualFindingCloseButtonClickable() {
        return isClickable("closeModalButton");
    }

    public boolean isScanDeleted() {
        return driver.findElementByLinkText("0 Scans").isDisplayed();
    }

    public boolean isSeverityLevelShown(String level) {
        return driver.findElementsById("expand" + level).size() != 0;
    }

    public boolean isVulnerabilityCountCorrect(String level, String expected) {
        return expected.equals(driver.findElementById("totalBadge" + level).getText().trim());
    }

    public boolean isVulnerabilityCountNonZero(String level) {
        return "0".equals(driver.findElementById("totalBadge" + level).getText().trim());
    }

    public boolean areAllVulnerabilitiesHidden() {
        return driver.findElementById("noResultsFound").getText().trim().equals("No results found.");
    }

    public boolean isSavedFilterSuccessMessageDisplayed() {
        return driver.findElementById("saveFilterSuccessMessage").isDisplayed();
    }

    public boolean isDuplicateNameErrorMessageDisplayed() {
        return driver.findElementById("saveFilterErrorMessage").isDisplayed();
    }

    public boolean isSaveFilterDisabled() {
        String attributeValue = driver.findElementById("saveFilterButton").getAttribute("disabled");
        if (attributeValue != null) {
            return attributeValue.contains("true");
        }
        return false;
    }

    public boolean isSavedFilterPresent(String savedFilter) {
        try {
            new Select(driver.findElementById("filterSelect")).selectByVisibleText(savedFilter);
            return true;
        } catch (org.openqa.selenium.NoSuchElementException e) {
            return false;
        }
    }
}
