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

import org.apache.commons.lang.RandomStringUtils;
import org.openqa.selenium.*;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertTrue;

public abstract class BasePage {
	
	public final static int NUM_SECONDS_TO_WAIT = 20;
	
	protected RemoteWebDriver driver;
	
	public BasePage(WebDriver webdriver){
		driver =  (RemoteWebDriver) webdriver;
		driver.manage().timeouts().implicitlyWait(NUM_SECONDS_TO_WAIT, TimeUnit.SECONDS);
        Dimension dimensions = new Dimension(1250,1020);
        driver.manage().window().setSize(dimensions);
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
		sleep(2000);
        waitForElement(driver.findElementById("apiKeysLink"));
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
        driver.findElementById("defectTrackersLink").click();
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
        waitForElement(driver.findElementById("currentPasswordInput"));
        return new UserChangePasswordPage(driver);
	}
	
	public UserIndexPage clickManageUsersLink(){
		clickConfigTab();
		driver.findElementById("manageUsersLink").click();
		sleep(3000);
		return new UserIndexPage(driver);
	}

    public FilterPage clickManageFiltersLink() {
        clickConfigTab();
        driver.findElementById("vulnFiltersLink").click();
        sleep(3000);
        return new FilterPage(driver);
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
        return isClickable("dashboardHeader");
	}
	
	public boolean isApplicationMenuLinkPresent(){
		return driver.findElementById("orgHeader").isDisplayed();
	}
	
	public boolean isApplicationMenuLinkClickable(){
        return isClickable("orgHeader");
	}
	
	public boolean isScansMenuLinkPresent(){
		return driver.findElementById("scansHeader").isDisplayed();
	}
	
	public boolean isScansMenuLinkClickable(){
        return isClickable("scansHeader");
	}
	
	public boolean isReportsMenuLinkPresent(){
		return driver.findElementById("reportsHeader").isDisplayed();
	}
	
	public boolean isReportsMenuLinkClickable(){
        return isClickable("reportsHeader");
	}
	
	public boolean isUsersMenuLinkPresent(){
		return driver.findElementById("tabUserAnchor").isDisplayed();
	}
	
	public boolean isUsersMenuLinkClickable(){
        return isClickable("tabUserAnchor");
	}
	
	public boolean isConfigMenuLinkPresent(){
		return driver.findElementById("tabConfigAnchor").isDisplayed();
	}
	
	public boolean isConfigMenuLinkClickable(){
        return isClickable("tabConfigAnchor");
	}
	
	public boolean isLogoPresent(){
		return driver.findElementById("logo").isDisplayed();
	}
	
	public boolean isLogoClickable(){
        return isClickable("logo");
	}
	
	public boolean isApiKeysLinkPresent(){
		return driver.findElementById("apiKeysLink").isDisplayed();
	}
	
	public boolean isApiKeysMenuLinkClickable(){
        return isClickable("apiKeysLink");
	}
	
	public boolean isWafsLinkPresent(){
		return driver.findElementById("wafsLink").isDisplayed();
	}
	
	public boolean isWafsMenuLinkClickable(){
        return isClickable("wafsLink");
	}
	
	public boolean isDefectTrackerLinkPresent(){
		return driver.findElementById("defectTrackersLink").isDisplayed();
	}
	
	public boolean isDefectTrackerMenuLinkClickable(){
        return isClickable("defectTrackersLink");
	}
	
	public boolean isRemoteProvidersLinkPresent(){
		return driver.findElementById("remoteProvidersLink").isDisplayed();
	}
	
	public boolean isRemoteProvidersMenuLinkClickable(){
        return isClickable("remoteProvidersLink");
	}
	
	public boolean isManageUsersLinkPresent(){
		return driver.findElementById("manageUsersLink").isDisplayed();
	}
	
	public boolean isManageUsersMenuLinkClickable(){
        return isClickable("manageUsersLink");
	}
	
	public boolean isManageRolesLinkPresent(){
		return driver.findElementById("manageRolesLink").isDisplayed();
	}
	
	public boolean isManageRolesMenuLinkClickable(){
        return isClickable("manageRolesLink");
	}

    public boolean isManageFiltersMenuLinkPresent(){
        return driver.findElementById("vulnFiltersLink").isDisplayed();
    }

    public boolean isManageFiltersMenuLinkClickable(){
        return isClickable("vulnFiltersLink");
    }

	public boolean isLogsLinkPresent(){
		return driver.findElementById("viewLogsLink").isDisplayed();
	}
	
	public boolean isLogsMenuLinkClickable(){
        return isClickable("viewLogsLink");
	}
	
	public boolean isConfigureDefaultsLinkPresent(){
		return driver.findElementById("configureDefaultsLink").isDisplayed();
	}
	
	public boolean isConfigureDefaultsMenuLinkClickable(){
        return isClickable("configureDefaultsLink");
	}
	
	public boolean isConfigDropDownPresent(){
		return driver.findElementById("configurationHeader").isDisplayed();
	}
	
	public boolean isChangePasswordLinkPresent(){
		return driver.findElementById("changePasswordLink").isDisplayed();
	}
	
	public boolean isChangePasswordMenuLinkClickable(){
        return isClickable("changePasswordLink");
	}
	
	public boolean isToggleHelpLinkPresent(){
		return driver.findElementById("toggleHelpLink").isDisplayed();
	}
	
	public boolean isToggleHelpMenuLinkClickable(){
        return isClickable("toggleHelpLink");
	}
	
	public boolean isLogoutLinkPresent(){
		return driver.findElementById("logoutLink").isDisplayed();
	}
	
	public boolean isLogoutMenuLinkClickable(){
        return isClickable("logoutLink");
	}
	
	public boolean isUserDropDownPresent(){
        return driver.findElementById("userConfigurationHeader").isDisplayed();
	}

    // wrapper method for testing expected condition
    public boolean isClickable(String elementID) {
        ExpectedCondition<WebElement> condition = ExpectedConditions.elementToBeClickable(
                driver.findElementById(elementID)) ;

        return condition.apply(driver) != null;

    }

    public boolean isElementVisible(String elementID){
        ExpectedCondition<WebElement> condition = ExpectedConditions.visibilityOf(driver.findElementById(elementID));
        return condition.apply(driver) != null;
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
		WebDriverWait wait = new WebDriverWait(driver,30);
		wait.until(ExpectedConditions.visibilityOf(e));
	}
	
	public void waitForInvisibleElement(WebElement e){
		WebDriverWait wait = new WebDriverWait(driver,10);
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id(e.getAttribute("id"))));
	}
	
	protected static String getRandomString(int length) {
		return RandomStringUtils.random(length,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	}

    public boolean tryClick(By by) {
        int attempts = 0;
        boolean result = false;
        while (attempts < 2) {
            try {
                driver.findElement(by).click();
                result = true;
                break;
            } catch (StaleElementReferenceException e) {
                System.err.print("Attempting to avoid StaleElementReferenceException.");
            }
            attempts++;
        }
        return result;
    }

    public String tryGetText(By by) {
        int attempts = 0;
        String result = null;
        while (attempts < 2) {
            try {
                result = driver.findElement(by).getText();
                break;
            } catch (StaleElementReferenceException e) {
                System.err.print("Attempting to avoid StaleElementReferenceException.");
            }
            attempts++;
        }
        if (result == null) {
            throw new NoSuchElementException("Element not found.");
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public <T extends BasePage> T clickModalSubmit() {
        return (T) clickModalSubmit(this.getClass());
    }

    @SuppressWarnings("unchecked")
    public <T extends BasePage> T clickModalSubmit(Class<T> targetClass) {
        driver.findElementById("submit").click();
        sleep(2000);
        assertTrue("Submit button still present.", driver.findElementsById("submit").size() == 0);

        return (T) this;
    }

    @SuppressWarnings("unchecked")
    public <T extends BasePage> T clickModalSubmitInvalid() {
        return (T) clickModalSubmitInvalid(this.getClass());
    }

    @SuppressWarnings("unchecked")
    public <T extends BasePage> T clickModalSubmitInvalid(Class<T> targetClass) {
        driver.findElementById("submit").click();

        assertTrue("Submit button wasn't still present.", driver.findElementsById("submit").size() != 0);

        return (T) this;
    }

    @SuppressWarnings("unchecked")
    public <T extends BasePage> T clickModalCancel() {
        return (T) clickModalCancel(this.getClass());
    }

    @SuppressWarnings("unchecked")
    public <T extends BasePage> T clickModalCancel(Class<T> targetClass) {
        driver.findElementById("closeModalButton").click();
        sleep(500);
        assertTrue("Close button wasn't still present.", driver.findElementsById("closeModalbutton").size() == 0);

        return (T) this;
    }
}
