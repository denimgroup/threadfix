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
import java.util.concurrent.TimeUnit;

import com.denimgroup.threadfix.selenium.tests.TeamIndexCache;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

public abstract class BasePage {
	
	protected final Log log = LogFactory.getLog(this.getClass());
	
	public final static int NUM_SECONDS_TO_WAIT = 20;
	
	protected RemoteWebDriver driver;
	
	public BasePage(WebDriver webdriver){
		driver =  (RemoteWebDriver) webdriver;
		driver.manage().timeouts().implicitlyWait(NUM_SECONDS_TO_WAIT, TimeUnit.SECONDS);
		driver.manage().window().maximize();
		log.debug("Loading " + this.getClass().toString());
	}
	/*--------------click functions--------------*/
	public LoginPage logout() {
		clickUserTab();
//		waitForElement(driver.findElementById("configurationHeader"));
		sleep(2000);
		driver.findElementById("logoutLink").click();
		sleep(6000);
		waitForElement(driver.findElementById("login"));
        sleep(3000);
        /*
        sleep(3000);
		driver.navigate().refresh();
        sleep(15000);
		System.out.println("refreshed");
		driver.get(LoginPage.url + "j_spring_security_logout");
		//sleep(2000);
		waitForElement(driver.findElementById("login"));
		*/
		return new LoginPage(driver);
	}

    public List<String> getList() {
        List<String> teamIndexMap = new ArrayList<>();

        for (int j = 1; j <= getNumTeamRows(); j++) {
            WebElement element = driver.findElementById("teamName" + j);
            teamIndexMap.add(element.getText());
        }

        return teamIndexMap;
    }

    public int getNumTeamRows() {
        if (!(driver.findElementById("teamTable").getText().equals("Add Team"))) {
            return driver.findElementsByClassName("pointer").size();
        }
        return 0;
    }

	public TeamIndexPage clickOrganizationHeaderLink() {
            driver.findElementById("orgHeader").click();
			sleep(2000);

            TeamIndexCache cache = TeamIndexCache.getCache();

            if (!cache.isInitialized()) {
                cache.initialize(getList());
            }

            /*System.out.println("\nCache is initialized or Applications link clicked.");
            cache.printList();*/

			return new TeamIndexPage(driver);
	}
	
	public ScanIndexPage clickScansHeaderLink(){
		driver.findElementById("scansHeader").click();
		sleep(1000);
		return new ScanIndexPage(driver);
	}
	
	public WafIndexPage clickWafsHeaderLink() {
		clickConfigTab();
		driver.findElementById("wafsLink").click();
		sleep(1000);
		return new WafIndexPage(driver);
	}

	public ReportsIndexPage clickReportsHeaderLink() {
		driver.findElementById("reportsHeader").click();
		waitForElement(driver.findElementByTagName("h2"));
		return new ReportsIndexPage(driver);
	}
	
	public void clickConfigTab(){
		driver.findElementById("tabConfigAnchor").click();
		sleep(3000);
	}
	
	public void clickUserTab(){
		driver.findElementById("tabUserAnchor").click();
        sleep(3000);
	}
	
	
	
	public ApiKeysIndexPage clickApiKeysLink(){
		clickConfigTab();
		driver.findElementById("apiKeysLink").click();
		return new ApiKeysIndexPage(driver);
	}
	
	public DefectTrackerIndexPage clickDefectTrackersLink(){
		clickConfigTab();
        WebElement defectLink = driver.findElementById("defectTrackersLink");
        defectLink.click();
		sleep(4000);
		return new DefectTrackerIndexPage(driver);
	}
	
	public RemoteProvidersIndexPage clickRemoteProvidersLink(){
		clickConfigTab();
		driver.findElementById("remoteProvidersLink").click();
		sleep(6000);
		return new RemoteProvidersIndexPage(driver);
	}
	
	public UserChangePasswordPage clickChangePasswordLink(){
		clickUserTab();
		driver.findElementById("changePasswordLink").click();
        sleep(6000);
        waitForElement(driver.findElementById("currentPasswordInput"));
        return new UserChangePasswordPage(driver);
	}
	
	public UserIndexPage clickManageUsersLink(){
		clickConfigTab();
		driver.findElementById("manageUsersLink").click();
		sleep(3000);
		return new UserIndexPage(driver);
	}
	
	public RolesIndexPage clickManageRolesLink(){
		clickConfigTab();
		driver.findElementById("manageRolesLink").click();
		sleep(3000);
		return new RolesIndexPage(driver);
	}
	
	public ErrorLogPage clickViewLogsLink(){
		clickConfigTab();
		driver.findElementById("viewLogsLink").click();
		return new ErrorLogPage(driver);
	}
	
	public ConfigureDefaultsPage clickConfigureDefaultsLink(){
		clickConfigTab();
		driver.findElementById("configureDefaultsLink").click();
		return new ConfigureDefaultsPage(driver);
		
	}
	
	public DashboardPage clickDashboardLink(){
		driver.findElementById("dashboardHeader").click();
		sleep(1000);
		return new DashboardPage(driver);
	}
	
	
	/*--------------get functions--------------*/
	public boolean isElementPresent(String elementId) {
		try {
			return driver.findElementById(elementId) != null;
		} catch (NoSuchElementException e) {
			return false;
		}
	}
	
	public String getH2Tag() {
		return driver.findElementByTagName("h2").getText();
	}

	public boolean isLoggedInUser(String user){
		return driver.findElementById("tabUserAnchor").getText().trim().contains(user);
	}
	
	public boolean isDashboardMenuLinkPresent(){
		return driver.findElementById("dashboardHeader").isDisplayed();
	}
	
	public boolean isDashboardMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("dashboardHeader")) != null;
	}
	
	public boolean isApplicationMenuLinkPresent(){
		return driver.findElementById("orgHeader").isDisplayed();
	}
	
	public boolean isApplicationMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("orgHeader")) != null;
	}
	
	public boolean isScansMenuLinkPresent(){
		return driver.findElementById("scansHeader").isDisplayed();
	}
	
	public boolean isScansMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("scansHeader")) != null;
	}
	
	public boolean isReportsMenuLinkPresent(){
		return driver.findElementById("reportsHeader").isDisplayed();
	}
	
	public boolean isReportsMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("reportsHeader")) != null;
	}
	
	public boolean isUsersMenuLinkPresent(){
		return driver.findElementById("tabUserAnchor").isDisplayed();
	}
	
	public boolean isUsersMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("tabUserAnchor")) != null;
	}
	
	public boolean isConfigMenuLinkPresent(){
		return driver.findElementById("tabConfigAnchor").isDisplayed();
	}
	
	public boolean isConfigMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("tabConfigAnchor")) != null;
	}
	
	public boolean isLogoPresent(){
		return driver.findElementById("logo").isDisplayed();
	}
	
	public boolean isLogoClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("logo")) != null;
	}
	
	public boolean isApiKeysLinkPresent(){
		return driver.findElementById("apiKeysLink").isDisplayed();
	}
	
	public boolean isApiKeysMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("apiKeysLink")) != null;
	}
	
	public boolean isWafsLinkPresent(){
		return driver.findElementById("wafsLink").isDisplayed();
	}
	
	public boolean isWafsMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("wafsLink")) != null;
	}
	
	public boolean isDefectTrackerLinkPresent(){
		return driver.findElementById("defectTrackersLink").isDisplayed();
	}
	
	public boolean isDefectTrackerMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("defectTrackersLink")) != null;
	}
	
	public boolean isRemoteProvidersLinkPresent(){
		return driver.findElementById("remoteProvidersLink").isDisplayed();
	}
	
	public boolean isRemoteProvidersMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("remoteProvidersLink")) != null;
	}
	
	public boolean isManageUsersLinkPresent(){
		return driver.findElementById("manageUsersLink").isDisplayed();
	}
	
	public boolean isManageUsersMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("manageUsersLink")) != null;
	}
	
	public boolean isManageRolesLinkPresent(){
		return driver.findElementById("manageRolesLink").isDisplayed();
	}
	
	public boolean isManageRolesMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("manageRolesLink")) != null;
	}
	
	public boolean isLogsLinkPresent(){
		return driver.findElementById("viewLogsLink").isDisplayed();
	}
	
	public boolean isLogsMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("viewLogsLink")) != null;
	}
	
	public boolean isConfigureDefaultsLinkPresent(){
		return driver.findElementById("configureDefaultsLink").isDisplayed();
	}
	
	public boolean isConfigureDefaultsMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("configureDefaultsLink")) != null;
	}
	
	public boolean isConfigDropDownPresent(){
		return driver.findElementById("tab-config").findElement(By.id("ConfigurationHeader")).isDisplayed();
	}
	
	public boolean isChangePasswordLinkPresent(){
		return driver.findElementById("changePasswordLink").isDisplayed();
	}
	
	public boolean isChangePasswordMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("changePasswordLink")) != null;
	}
	
	public boolean isToggleHelpLinkPresent(){
		return driver.findElementById("toggleHelpLink").isDisplayed();
	}
	
	public boolean isToggleHelpMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("toggleHelpLink")) != null;
	}
	
	public boolean isLogoutLinkPresent(){
		return driver.findElementById("logoutLink").isDisplayed();
	}
	
	public boolean isLogoutMenuLinkClickable(){
		return ExpectedConditions.elementToBeClickable(By.id("logoutLink")) != null;
	}
	
	public boolean isUserDropDownPresent(){
		return true;
//		return driver.findElementById("tab-user").findElement(By.id("ConfigurationHeader")).isDisplayed();
	}
	
	
	
	/*--------------helper functions--------------*/
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public void waitForElementPresence(String element, int number) {
		int count = 0;
		// wait til jsonResult2 is present
		while (!isElementPresent(element)) {
			sleep(1000);
			if (count++ > number) {
				return;
			}
		}
	}
	
	protected void handleAlert() {
		sleep(3000);
		WebDriverWait wait = new WebDriverWait(driver,10);
		wait.until(ExpectedConditions.alertIsPresent());
		Alert alert = driver.switchTo().alert();
		alert.accept();
		sleep(2000);
	}
	
	public void waitForElement(WebElement e){
		WebDriverWait wait = new WebDriverWait(driver,20);
		wait.until(ExpectedConditions.visibilityOf(e));
	}
	
	public void waitForInvisibleElement(WebElement e){
		WebDriverWait wait = new WebDriverWait(driver,10);
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id(e.getAttribute("id"))));
	}
	
	protected static String getRandomString(int length) {
		return RandomStringUtils.random(length,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	}
}
