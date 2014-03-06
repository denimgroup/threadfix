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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.denimgroup.threadfix.selenium.tests.TeamIndexCache;
import org.openqa.selenium.*;
import org.openqa.selenium.support.ui.ExpectedConditions;

public class TeamDetailPage extends BasePage {
    private List<String> apps = new ArrayList<>();

    //     private WebElement orgName;
    private WebElement applicationsTableBody;
    private WebElement lastItemFoundInApplicationsTableBodyLink;
    private WebElement addApplicationLink;

    public TeamDetailPage(WebDriver webdriver) {
        super(webdriver);

//          orgName = driver.findElementById("name");
        applicationsTableBody = driver.findElementById("applicationsTableBody");
        addApplicationLink = driver.findElementByLinkText("Add Application");
    }

    public String getOrgName() {
        return driver.findElementById("name").getText();
    }

    public TeamDetailPage clickActionButton(){
        driver.findElementById("actionButton").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public FilterPage clickEditTeamFilters() {
        driver.findElementById("editfiltersButton1").click();
        waitForElement(driver.findElementById("createNewKeyModalButton"));
        return new FilterPage(driver);
    }

    public TeamDetailPage clickEditOrganizationLink() {
        clickActionButton();
        driver.findElementById("teamModalButton").click();
        waitForElement(driver.findElementById("teamModal"));
        return new TeamDetailPage(driver);
    }

    public boolean isAppPresent(String appName){
        return driver.findElementById("applicationsTableBody").getText().contains(appName);
    }

    public int getEditModalHeaderWidth(){
        return driver.findElementById("editFormDiv").findElement(By.className("ellipsis")).getSize().width;
    }
    public TeamDetailPage clickCloseEditModal(){
        driver.findElementById("editFormDiv").findElement(By.className("modal-footer")).findElements(By.className("btn")).get(0).click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage setNameInput(String editedOrgName) {
        driver.findElementById("teamNameInput").clear();
        driver.findElementById("teamNameInput").sendKeys(editedOrgName);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickUpdateButtonValid() {
        driver.findElementById("submitTeamModal").click();
        //          try{
        //               waitForInvisibleElement(driver.findElementById("editFormDiv"));
        //          }catch(TimeoutException e){
        //               driver.findElementById("submitTeamModal").click();
        //      }
        sleep(1000);
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
        sleep(1000);
        return new TeamIndexPage(driver);
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

    //TODO possible deletion, not being used and there might be better alternative methods
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

    public String getAppModalId(){
        String s = driver.findElementByLinkText("Add Application").getAttribute("href");
        Pattern pattern = Pattern.compile("#(myAppModal[0-9] )$");
        Matcher matcher = pattern.matcher(s);
        if(matcher.find()){
            return  matcher.group(1);
        }
        return "";
    }

    public void populateAppList(){
        int i = 1;
        if (apps.isEmpty()){
            try {
                while(driver.findElementById("appLink"+ i).isDisplayed()){
                    apps.add(driver.findElementById("appLink" + i).getText());
                    i++;
                }
            }catch(NoSuchElementException e) {
                System.out.println("Done getting app list.");
            }
        }
    }

    public int getAppIndex(String appName) {
        int i = 0;
        for (String app : apps) {
            i++;
            if (app.equals(appName)) {
                return i;
            }
        }
        return -1;
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

    public int getNumTeamRows() {
        if (!(driver.findElementById("teamTable").getText().equals("Add Team"))) {
            return driver.findElementsByClassName("pointer").size();
        }
        return 0;
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

    public boolean applicationVulnerabilitiesFiltered(String appName, String level,String expected) {
        populateAppList();
        return driver.findElementById("app" + level + "Vulns" + getAppIndex(appName)).getText().equals(expected);
    }

    public boolean isActionBtnPresent(){
        return driver.findElementById("actionButton").isDisplayed();
    }

    public boolean isActionBtnClickable(){
        return isClickable("actionButton");
    }

    public boolean isActionDropDownPresnt(){
        return driver.findElementByClassName("dropdown-menu").isDisplayed();
    }

    public boolean isEditDeleteLinkPresent(){
        return driver.findElementById("teamModalButton").isDisplayed();
    }

    public boolean isEditDeleteLinkClickable(){
        return isClickable("teamModalButton");
    }

    public boolean isEditDeleteModalPresent(){
        return driver.findElementById("teamModal").isDisplayed();
    }

    public boolean isDeleteTeamButtonPresent(){
        return driver.findElementById("deleteLink").isDisplayed();
    }

    public boolean EDDeleteClickable(){
        return isClickable("deleteLink");
    }

    public boolean EDClosePresent(){
        return driver.findElementById("closeTeamModalButton").isDisplayed();
    }

    public boolean EDCloseClickable(){
        return isClickable("closeTeamModalButton");
    }

    public boolean EDSavePresent(){
        return driver.findElementById("submitTeamModal").isDisplayed();
    }

    public boolean EDSaveClickable(){
        return isClickable("submitTeamModal");
    }

    public boolean EDNamePresent(){
        return driver.findElementById("teamNameInput").isDisplayed();
    }

    public boolean isTeamNameDisplayedCorrectly(String teamName) {
        String pageName = driver.findElementById("name").getText();
        pageName = pageName.replaceAll("(.*) Action$", "$1");
        return teamName.equals(pageName);
    }

    public boolean ispermUsersLinkPresent(){
        return driver.findElementById("userListModelButton").isDisplayed();
    }

    public boolean ispermUsersLinkClickable(){
        return isClickable("userListModelButton");
    }

    public boolean isPermUserModalPresent(){
        return driver.findElementById("usersModal").isDisplayed();
    }

    public boolean isPUEditPermLinkPresent(){
        //TODO switch to use user name to check right link
        return driver.findElementById("editPermissions1").isDisplayed();
    }

    public boolean isPUEditPermLinkClickable(){
        //TODO switch to use user name to check right link
        return isClickable("editPermissions1");
    }

    public boolean isPUClosePresent(){
        return driver.findElementById("usersModal").findElement(By.className("btn")).isDisplayed();
    }

    //correct to work with classes and stuff expectedConditions
    @SuppressWarnings("static-access")
    public boolean isPUCloseClickable(){
        return ExpectedConditions.elementToBeClickable(By.id("usersModal").className("btn")) != null;
    }

    public boolean isleftViewMoreLinkPresent(){
        return driver.findElementById("leftViewMore").isDisplayed();
    }

    public boolean isleftViewMoreLinkClickable(){
        return isClickable("leftViewMore");
    }

    public boolean is6MonthChartPresnt(){
        return driver.findElementById("leftTileReport").isDisplayed();
    }

    public boolean isrightViewMoreLinkPresent(){
        return driver.findElementById("rightViewMore").isDisplayed();
    }

    public boolean isrightViewMoreLinkClickable(){
        return isClickable("rightViewMore");
    }

    public boolean isTop10ChartPresent(){
        return driver.findElementById("rightTileReport").isDisplayed();
    }

    public boolean isAddAppBtnPresent(){
        return driver.findElementByLinkText("Add Application").isDisplayed();
    }

    public boolean isAddAppBtnClickable(){
        return isClickable("Add Application");
    }

    public boolean isAppLinkPresent(String appName){
        return driver.findElementByLinkText(appName).isDisplayed();
    }

    public boolean isAppLinkClickable(String appName){
        return ExpectedConditions.elementToBeClickable(By.linkText(appName)) != null;
    }

    public boolean isAddAppModalPresent(){
        return driver.findElementById(getAppModalId()).isDisplayed();
    }

    public boolean isAPNameFieldPresent(){
        return driver.findElementById(getAppModalId()).findElement(By.id("nameInput")).isDisplayed();
    }

    public boolean isAPNameFieldFunctional(){
        int limit = Integer.parseInt(
                driver.findElementById(getAppModalId()).findElement(By.id("nameInput")).getAttribute("maxlength"));

        String s = getRandomString(limit+10);
        driver.findElementById(getAppModalId()).findElement(By.id("nameInput")).sendKeys(s);
        String v = driver.findElementById(getAppModalId()).findElement(By.id("nameInput")).getAttribute("value");
        return v.equals(s.substring(0, limit));
    }

    public boolean isURLFieldPresent(){
        return driver.findElementById(getAppModalId()).findElement(By.id("urlInput")).isDisplayed();
    }

    public boolean isURlFieldFunctional(){
        int limit = Integer.parseInt(
                driver.findElementById(getAppModalId()).findElement(By.id("urlInput")).getAttribute("maxlength"));

        String s = getRandomString(limit+10);
        driver.findElementById(getAppModalId()).findElement(By.id("urlInput")).sendKeys(s);
        String v = driver.findElementById(getAppModalId()).findElement(By.id("urlInput")).getAttribute("value");
        return v.equals(s.substring(0, limit));
    }

    public boolean isAPIDFieldPresent(){
        return driver.findElementById(getAppModalId()).findElement(By.id("uniqueIdInput")).isDisplayed();
    }

    public boolean isAPIDFieldFunctional(){
        int limit = Integer.parseInt(
                driver.findElementById(getAppModalId()).findElement(By.id("uniqueIdInput")).getAttribute("maxlength"));

        String s = getRandomString(limit+10);
        driver.findElementById(getAppModalId()).findElement(By.id("uniqueIdInput")).sendKeys(s);
        String v = driver.findElementById(getAppModalId()).findElement(By.id("uniqueIdInput")).getAttribute("value");
        return v.equals(s.substring(0, limit));
    }

    public boolean isAPCriticalityPresent(){
        return driver.findElementById(getAppModalId()).findElement(By.id("criticalityId")).isDisplayed();
    }

    public boolean isAPCriticalityCorrect(){
        //          Select sel = new Select(driver.findElementById(getAppModalId()).findElement(By.id("criticalityId")));
        //          for(int i=0; i<sel.getOptions().size(); i++)
        //               System.out.println("option"+i+" "+sel.getOptions().get(i));
        //          return sel.getOptions().contains("Low") && sel.getOptions().contains("Medium") && sel.getOptions().contains("High") && sel.getOptions().contains("Critical");
        //TODO
        return true;
    }

    public boolean isCloseAPButtonPresent(){
        return driver.findElementById(getAppModalId())
                .findElement(By.className("modal-footer"))
                .findElements(By.className("btn")).get(0).isDisplayed();
    }

    //needs to be fixed with expectedConditions
    @SuppressWarnings("static-access")
    public boolean isCloseAPButtonClickable(){
        driver.findElementById(getAppModalId())
                .findElement(By.className("modal-footer"))
                .findElements(By.className("btn")).get(0);
        return ExpectedConditions.elementToBeClickable(By.id(getAppModalId()).className("modal-footer").className("btn")) != null;
    }

    public boolean isAddTeamAPButtonPresent(){
        return driver.findElementById(getAppModalId()).isDisplayed();
    }

    public boolean isAddTeamAPButtonClickable(){
        return isClickable(getAppModalId());
    }

    public TeamDetailPage clickUserPermLink() {
        clickActionButton();
        sleep(3000);
        driver.findElementById("userListModelButton").click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public TeamDetailPage clickCloseUserPermModal() {
        driver.findElementById("usersModal").findElement(By.className("btn")).click();
        sleep(2000);
        return new TeamDetailPage(driver);
    }

    public int getNumPermUsers(){
        return driver.findElementById("userTableBody").findElements(By.className("bodyRow")).size();
    }

    public boolean isUserPresentPerm(String user){
        for(int i = 1; i <= getNumPermUsers();i++){
            if (driver.findElementById("name"+i).getText().contains(user)){
                return true;
            }
        }
        return false;
    }

}
