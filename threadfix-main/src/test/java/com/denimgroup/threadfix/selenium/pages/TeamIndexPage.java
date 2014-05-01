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

import com.denimgroup.threadfix.selenium.tests.TeamIndexCache;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class TeamIndexPage extends BasePage {

    private List<WebElement> apps = new ArrayList<>();

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

    public int getNumAppRows(String index) {
        if (!(driver.findElementById("teamAppTableDiv" + (index))
                .getText().contains("No applications found."))) {
            return driver.findElementById("teamAppTable" + (index)).findElements(By.className("app-row")).size();
        }
        return 0;
    }

    @Deprecated
    public int getIndexSlow(String teamName) {
        System.out.println("Using slow map!");
        int i = -1;
        List<WebElement> names = new ArrayList<>();
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
        names = new ArrayList<>();
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

    @Deprecated
    public int getIndex(String teamName) {
        TeamIndexCache cache = TeamIndexCache.getCache();
        if (cache.getIndex(teamName) < 0) {
            return getIndexSlow(teamName) + 1;
        }
        return cache.getIndex(teamName);
    }

    @Deprecated
    public int getAppIndex(String appName){
        int i = -1;
        for(WebElement app : apps){
            i++;
            String text = app.getText().trim();
            if(text.equals(appName.trim())){
                return i + 1;
            }
        }
        return -1;
    }

    public TeamIndexPage clickAddTeamButton() {
        driver.findElementById("addTeamModalButton").click();
        waitForElement(driver.findElementById("myModalLabel"));
        return setPage();
    }

    public TeamIndexPage setTeamName(String name) {
        driver.findElementById("nameInput").clear();
        driver.findElementById("nameInput").sendKeys(name);
        return setPage();
    }

    public TeamIndexPage addNewTeam() {
        driver.findElementById("addTeamButton").click();

        String teamName = driver.findElementByClassName("alert-success").getText();
        teamName = teamName.substring(7,(teamName.length()-31));
        waitForElement(driver.findElementById("teamName"+teamName));

        sleep(1000);
        return setPage();
    }

    public TeamIndexPage addNewTeamInvalid() {
        driver.findElementById("addTeamButton").click();
        sleep(1000);
        return setPage();
    }

    public TeamIndexPage expandTeamRowByName(String teamName) {
        driver.findElementById("teamCaret" + teamName).click();
        return setPage();
    }

    public TeamIndexPage expandAllTeams() {
        driver.findElementById("expandAllButton").click();
        return setPage();
    }

    public TeamIndexPage collapseAllTeams() {
        driver.findElementById("collapseAllButton").click();
        return setPage();
    }


    public void populateAppList(String name){  //needs to be refactored to stuff and things
        apps = new ArrayList<>();
        sleep(5000);
        if (!driver.findElementById("teamAppTable" + (name))
                .getText().contains("No applications found.")) {
            sleep(2000);
            for (int j = 0; j < getNumAppRows(name); j++) {
                apps.add(
                        driver.findElementById(("applicationLink" + (name))
                                + "-" + (j + 1)));
            }
        }
    }

    public ApplicationDetailPage clickViewAppLink(String appName, String teamName) {
        driver.findElementById("applicationLink" + teamName + "-" + appName).click();
        return new ApplicationDetailPage(driver);
    }

    public TeamIndexPage clickAddNewApplication(String teamName) {
        driver.findElementById("addApplicationModalButton" + teamName).click();
        return setPage();
    }

    public TeamIndexPage setApplicationName(String appName, String teamName) {
        driver.findElementById("applicationNameInput").clear();
        driver.findElementById("applicationNameInput").sendKeys(appName);
        return setPage();
    }

    public TeamIndexPage setApplicationUrl(String url) {
        driver.findElementById("applicationUrlInput").clear();
        driver.findElementById("applicationUrlInput").sendKeys(url);
        return setPage();
    }

    public TeamIndexPage setApplicationCriticality(String criticality) {
        new Select(driver.findElementById("criticalityIdSelect")).selectByVisibleText(criticality);
        return setPage();
    }

    public TeamIndexPage saveApplication() {
        driver.findElementById("submit").click();
        sleep(3000);
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage saveApplicationInvalid() {
        driver.findElementById("submit").click();
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage clickCloseAddAppModal(){
        driver.findElementByLinkText("Close").click();
        return new TeamIndexPage(driver);
    }

    public TeamIndexPage addNewApplication(String teamName, String appName,String url, String criticality) {
        clickAddNewApplication(teamName);
        setApplicationName(appName, teamName);
        setApplicationUrl(url);
        setApplicationCriticality(criticality);
        return setPage();
    }

    public String getNameErrorMessage() {
        return driver.findElementById("applicationNameInputRequiredError").getText();
    }

    public String getUrlErrorMessage() {
        return driver.findElementById("applicationUrlInputInvalidUrlError").getText();
    }

    public boolean isAppPresent(String appName) {
        return driver.findElementByLinkText(appName).isDisplayed();
    }

    public TeamIndexPage setPage(){
        TeamIndexPage page = new TeamIndexPage(driver);
        page.modalNum = modalNum;
        page.appModalId = appModalId;
        return page;
    }

    public boolean isTeamPresent(String teamName) {
        return driver.findElementsById("teamName" + teamName).size() != 0;
    }

    public boolean isCreateValidationPresent(String teamName) {
        return driver
                .findElementByClassName("alert-success")
                .getText()
                .contains(
                        "Team " + teamName + " has been created successfully.");
    }

    public TeamDetailPage clickViewTeamLink(String teamName) {
        driver.findElementById("organizationLink" + teamName).click();
        sleep(4000);
		return new TeamDetailPage(driver);
	}

	public int modalNumber(String teamName, String appName){
        populateAppList(teamName);
        int appIndex = getAppIndex(appName);
		String s = driver.findElementById("uploadScanModalLink" + teamName + "-" + appIndex).getAttribute("href");
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
        return isClickable("addTeamModalButton");
	}

    public boolean areAllTeamsExpanded() {
        for (int i = 1; i <= getNumTeamRows(); i++){
            if (!(driver.findElementById("teamAppTableDiv" + i).isDisplayed())) {
                return false;
            }
        }
        return true;
    }

    public boolean areAllTeamsCollapsed() {
        for (int i = 1; i <= getNumTeamRows(); i++){
            if (driver.findElementById("teamAppTableDiv" + i).isDisplayed()) {
                return false;
            }
        }
        return true;
    }

	public boolean isExpandAllBtnPresent(){
		return driver.findElementById("expandAllButton").isDisplayed();	
	}
	
	public boolean isExpandAllBtnClickable(){
        return isClickable("expandAllButton");
	}
	
	public boolean isCollapseAllBtnPresent(){
		return driver.findElementById("collapseAllButton").isDisplayed();	
	}
	
	public boolean isCollapseAllBtnClickable(){
        return isClickable("collapseAllButton");
	}

    // TODO this needs to be changed so that it will use the img id and not a path
    public boolean isGraphDisplayed(String teamName, String appName) {
        modalNum = modalNumber(teamName, appName);
        String temp = "/threadfix/jasperimage/pointInTim" + modalNum + "/img_0_0_0";
        return driver.findElementByXPath(temp).isDisplayed();
    }

    public boolean teamVulnerabilitiesFiltered(String teamName, String level, String expected) {
        return driver.findElementById("num" + level + "Vulns" + teamName).getText().equals(expected);
    }

    public boolean applicationVulnerabilitiesFiltered(String teamName, String appName, String level, String expected) {
        return getApplicationSpecificVulnerability(teamName, appName, level).equals(expected);
    }

    public String getApplicationSpecificVulnerability(String teamName, String appName, String level) {
        return driver.findElement(By.id("num" + level + "Vulns" + teamName + "-" + appName)).getText();
    }

}
