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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerSchedulePage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class DefectTrackerIT extends BaseIT {

    private static final String JIRA_USERNAME = System.getProperty("JIRA_USERNAME");
    private static final String JIRA_PASSWORD = System.getProperty("JIRA_PASSWORD");
    private static final String JIRA_URL = System.getProperty("JIRA_URL");
    private static final String JIRAPROJECTNAME = System.getProperty("JIRAPROJECTNAME");
    private static final String BUGZILLA_USERNAME = System.getProperty("BUGZILLA_USERNAME");
    private static final String BUGZILLA_PASSWORD = System.getProperty("BUGZILLA_PASSWORD");
    private static final String BUGZILLA_URL = System.getProperty("BUGZILLA_URL");
    private static final String BUGZILLAPROJECTNAME = "For ThreadFix";
    private static final String HPQUALITYCENTER_URL = System.getProperty("HPQUALITYCENTER_URL");
    private static final String TFS_USERNAME = System.getProperty("TFS_USERNAME");
    private static final String TFS_PASSWORD = System.getProperty("TFS_PASSWORD");
    private static final String TFS_URL = System.getProperty("TFS_URL");
    private static final String TFS_PROJECTNAME = ("Vulnerability Manager Demo");

    static {
        if (JIRA_USERNAME == null){
            throw new RuntimeException("Please set JIRA_USERNAME property.");
        }
        if (JIRA_PASSWORD == null){
            throw new RuntimeException("Please set JIRA_PASSWORD property.");
        }
        if (JIRA_URL == null){
            throw new RuntimeException("Please set JIRA_URL property.");
        }
        if (JIRAPROJECTNAME == null){
            throw new RuntimeException("Please set JIRAPROJECTNAME property.");
        }
        if (BUGZILLA_USERNAME == null){
            throw new RuntimeException("Please set BUGZILLA_USERNAME property.");
        }
        if (BUGZILLA_PASSWORD == null){
            throw new RuntimeException("Please set BUGZILLA PASSWORD property.");
        }
        if (BUGZILLA_URL == null){
            throw new RuntimeException("Please set BUGZILLA_URL property.");
        }
        if (TFS_USERNAME == null){
            throw new RuntimeException("Please set TFS_USERNAME property.");
        }
        if (TFS_PASSWORD == null){
            throw new RuntimeException("Please set TFS_PASSWORD property.");
        }
        if (TFS_URL == null){
            throw new RuntimeException("Please set TFS_URL property.");
        }
    }

    @Test
	public void createDefectTrackerTest() {
		String newDefectTrackerName = getName();
		String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

		defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(newDefectTrackerName)
				.setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        assertTrue("Success message error.",
                defectTrackerIndexPage.getSuccessMessage().contains("Successfully created defect tracker " + newDefectTrackerName));

		assertTrue("The defectTracker was not present in the table.",
                defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
	}

    @Test
    public void deleteDefectTrackerTest() {
        String newDefectTrackerName = getName();
        String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickAddDefectTrackerButton()
                .setName(newDefectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(newDefectTrackerName)
                .clickDeleteButton()
                .clickDefectTrackersLink();

        assertFalse("The defectTracker was still present after attempted deletion.",
                defectTrackerIndexPage.isElementPresent("defectTackerName" + newDefectTrackerName));
    }

	@Test
	public void createDefectTrackerFieldValidation() {
		String emptyString = "";
		String whiteSpaceString = "           ";
		String urlFormatString = "asdfwe";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickAddDefectTrackerButton();

		//Test empty and whitespace input
		defectTrackerIndexPage = defectTrackerIndexPage.setName(emptyString)
                .setURL(emptyString)
				.clickAddDefectTrackerButtonInvalid();

        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameRequiredError"));
        assertTrue("The correct error text was not present",defectTrackerIndexPage.getNameRequiredErrorsText().contains("Name is required."));

		defectTrackerIndexPage = defectTrackerIndexPage.setName(whiteSpaceString)
				.setURL(whiteSpaceString)
				.clickAddDefectTrackerButtonInvalid();

        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameRequiredError"));
        assertTrue("The correct error text was not present",defectTrackerIndexPage.getNameRequiredErrorsText().contains("Name is required."));

		// Test URL format checking
		defectTrackerIndexPage = defectTrackerIndexPage.setName("normal name")
                .setURL(urlFormatString)
				.clickAddDefectTrackerButtonInvalid();

        assertTrue("The URL format check error text was not present.",defectTrackerIndexPage.isElementVisible("urlInvalidError"));
	}

    @Test
    public void longNameFormatTest() {
        String longName = getRandomString(60);
        String longNameFormatted = longName.substring(0,49);

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickAddDefectTrackerButton();

        defectTrackerIndexPage.setName(longName)
                .setURL(BUGZILLA_URL)
                .setType("Bugzilla")
                .clickSaveDefectTracker();

        assertTrue("Success message error.",
                defectTrackerIndexPage.getSuccessMessage().contains("Successfully created defect tracker " + longNameFormatted));

        assertTrue("The defectTracker was not present in the table.",
                defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(longNameFormatted));
    }

	@Test
	public void editDefectTrackerTest() {
		String originalDefectTrackerName = getName();
		String editedDefectTrackerName = getName();
		String originalDefectTrackerType = "Jira";
        String editedDefectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(originalDefectTrackerName)
                .setType(originalDefectTrackerType)
				.setURL(JIRA_URL)
                .clickSaveDefectTracker();

        defectTrackerIndexPage.refreshPage();

        //Edit previously created defect tracker
		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(originalDefectTrackerName)
                .setName(editedDefectTrackerName)
                .setType(editedDefectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

		assertTrue("Edit did not change the name.",
                defectTrackerIndexPage.isNamePresent(editedDefectTrackerName));
        assertTrue("Edit did not change the type.",
                defectTrackerIndexPage.isTypeCorrect(editedDefectTrackerType, editedDefectTrackerName));
        assertTrue("Edit did not change url.",
                defectTrackerIndexPage.isUrlCorrect(BUGZILLA_URL, editedDefectTrackerName));
	}

    @Test
	public void editDefectTrackerFieldValidation() {
        String emptyString = "";
        String whiteSpaceString = "           ";

		String newDefectTrackerName = getName();
		String defectTrackerNameDuplicateTest = getName();

		String defectTrackerType = "Bugzilla";
        String longInput = getRandomString(55);

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

        defectTrackerIndexPage.clickAddDefectTrackerButton();
        defectTrackerIndexPage.setName(defectTrackerNameDuplicateTest);
        defectTrackerIndexPage.setType(defectTrackerType);
        defectTrackerIndexPage.setURL(BUGZILLA_URL);
        defectTrackerIndexPage.clickSaveDefectTracker();

        defectTrackerIndexPage.refreshPage();

		defectTrackerIndexPage.clickAddDefectTrackerButton();
        defectTrackerIndexPage.setName(newDefectTrackerName);
        defectTrackerIndexPage.setType(defectTrackerType);
        defectTrackerIndexPage.setURL(BUGZILLA_URL);
        defectTrackerIndexPage.clickSaveDefectTracker();

        defectTrackerIndexPage.refreshPage();

        defectTrackerIndexPage.clickEditLink(newDefectTrackerName);

		// Test empty and whitespace input
		defectTrackerIndexPage.setName(emptyString);
        defectTrackerIndexPage.clickModalSubmitInvalid();
        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameRequiredError"));
		assertTrue("The correct error text was not present",defectTrackerIndexPage.getNameRequiredErrorsText().contains("Name is required."));

		defectTrackerIndexPage.setName(whiteSpaceString);
        defectTrackerIndexPage.clickModalSubmitInvalid();
        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameRequiredError"));
		assertTrue("The correct error text was not present",defectTrackerIndexPage.getNameRequiredErrorsText().contains("Name is required."));

		// Test browser length limit
		defectTrackerIndexPage.setName(longInput);
        defectTrackerIndexPage.clickModalSubmitInvalid();
        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameCharacterLimitError"));

        defectTrackerIndexPage.clickModalCancel();
        defectTrackerIndexPage.refreshPage();

		// Test name duplication checking
		defectTrackerIndexPage.clickDefectTrackersLink();
        defectTrackerIndexPage.clickEditLink(newDefectTrackerName);
        defectTrackerIndexPage.setName(defectTrackerNameDuplicateTest);
        defectTrackerIndexPage.clickModalSubmitInvalid();
        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameServerError"));
        assertTrue("The correct error text was not present",defectTrackerIndexPage.getNameDuplicateErrorsText().contains("That name is already taken."));
	}

	@Test
	public void jiraEdit() {
		String defectTrackerName = getName();
        String replacementName = getName();
		String defectTrackerType = "Jira";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(JIRA_URL)
                .clickSaveDefectTracker();

        defectTrackerIndexPage.refreshPage();

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(defectTrackerName)
                .setName(replacementName)
                .clickSaveDefectTracker();

		assertTrue("DefectTracker page did not edit jira tracker correctly.",
				defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(replacementName));
	}

	@Test
	public void bugzillaEdit() {
		String defectTrackerName = getName();
        String replacementName = getName();
		String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

        defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        driver.navigate().refresh();

        assertTrue("DefectTracker Page did not create correctly.",
                defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(defectTrackerName));

		defectTrackerIndexPage.clickEditLink(defectTrackerName)
                .setName(replacementName)
                .clickSaveDefectTracker();

		assertTrue("Success message error.",defectTrackerIndexPage.getSuccessMessage().contains("Successfully edited tracker " + replacementName));
        assertTrue("The defectTracker was not present in the table.",defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(replacementName));
    }

    @Test
    public void switchDefectTrackersTest() {
        String defectTracker1 = getName();
        String defectTracker2 = getName();
        String defectTrackerType = "Bugzilla";

        String teamName = createTeam();
        String appName = createApplication(teamName);

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTracker1)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink()
                .clickAddDefectTrackerButton()
                .setName(defectTracker2)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .addDefectTracker(defectTracker1, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);

        assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
        //assertTrue("Defect Tracker wasn't attached correctly",applicationDetailPage.getDefectTrackerName().contains(defectTracker1));

        applicationDetailPage = applicationDetailPage.clickModalCancel();
        sleep(500);
        applicationDetailPage.addDefectTracker(defectTracker2, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);

        assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
        //assertTrue("Defect Tracker wasn't attached correctly",applicationDetailPage.getDefectTrackerName().contains(defectTracker2));
    }

	@Test
	public void attachBugzillaTrackerTest() {
		String defectTrackerName = getName();
		String defectTrackerType = "Bugzilla";
		String teamName = getName();
		String appName = getName();

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(defectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);

		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
	}

    @Test
    public void deleteAttachedBugzillaTrackerTest() {
        String defectTrackerName = getName();
        String defectTrackerType = "Bugzilla";
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .addDefectTracker(defectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);

        defectTrackerIndexPage = applicationDetailPage.clickDefectTrackersLink()
                .clickEditLink(defectTrackerName)
                .clickDeleteButton()
                .clickDefectTrackersLink();

        assertFalse("The defectTracker was still present after attempted deletion.",
                defectTrackerIndexPage.isElementPresent("defectTackerName" + defectTrackerName));
    }

//TODO after HP quality Center machine comes up
    @Ignore
    @Test
    public void editDefectTrackerFromJiraToHP() {
        String originalDefectTrackerName = getName();
        String editedDefectTrackerName = getName();
        String originalDefectTrackerType = "Jira";
        String editedDefectTrackerType = "HP Quality Center";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(originalDefectTrackerName)
                .setType(originalDefectTrackerType)
                .setURL(JIRA_URL)
                .clickSaveDefectTracker();

        defectTrackerIndexPage.refreshPage();

        //Edit previously created defect tracker
        defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(originalDefectTrackerName)
                .setName(editedDefectTrackerName)
                .setType(editedDefectTrackerType)
                .setURL(HPQUALITYCENTER_URL)
                .clickSaveDefectTracker();

        assertTrue("Edit did not change the name.",
                defectTrackerIndexPage.isNamePresent(editedDefectTrackerName));
        assertTrue("Edit did not change the type.",
                defectTrackerIndexPage.isTypeCorrect(editedDefectTrackerType, editedDefectTrackerName));
        assertTrue("Edit did not change url.",
                defectTrackerIndexPage.isUrlCorrect(HPQUALITYCENTER_URL, editedDefectTrackerName));
    }

    @Test
    public void checkDefectTrackerPresentAfterEditing() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String defectTrackerName = getName();
        String replacementName = getName();
        String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setURL(BUGZILLA_URL)
                .setType(defectTrackerType)
                .clickSaveDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(appName)
                .addDefectTracker(defectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, "QA Testing");

        assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());

        defectTrackerIndexPage.clickDefectTrackersLink()
                .clickEditLink(defectTrackerName)
                .setName(replacementName)
                .clickSaveDefectTracker();

        applicationDetailPage.clickOrganizationHeaderLink()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        assertTrue("Defect tracker name wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerNameCorrect(replacementName));
    }

    /*------------------------------ Scheduling ------------------------------*/

    @Test
    public void checkDefectTrackerPage() {
        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

        assertTrue("Defect Tracker page wasn't showed", defectTrackerIndexPage.isCreateNewTrackerButtonPresent());
    }

    @Test
    public void defectTrackerDailyScheduling() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency("Daily")
                .setHour(1)
                .setMinute(15)
                .setPeriodOfDay("PM")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", defectTrackerSchedulePage.isNewSchedulePresent("_1_15_PM"));
    }

    @Test
    public void defectTrackerWeeklyScheduling() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency("Weekly")
                .setHour(8)
                .setMinute(15)
                .setPeriodOfDay("PM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created",
                defectTrackerSchedulePage.isNewSchedulePresent("Sunday_8_15_PM"));
    }

    @Test
    public void checkSameDailyScheduleConflict() {
        String frequency = "Daily";
        int hour = 9;
        int minutes = 30;
        String periodOfDay = "AM";

        DefectTrackerSchedulePage defectTrackerSchedulePage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency(frequency)
                .setHour(hour)
                .setMinute(minutes)
                .setPeriodOfDay(periodOfDay)
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", defectTrackerSchedulePage.isNewSchedulePresent("_9_30_AM"));

        defectTrackerSchedulePage.clickOrganizationHeaderLink()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency(frequency)
                .setHour(hour)
                .setMinute(minutes)
                .setPeriodOfDay(periodOfDay)
                .clickAddScheduledUpdated();

        assertTrue("Same Schedule was Created",
                defectTrackerSchedulePage.isErrorPresent("Another defect tracker update is scheduled at that time/frequency"));
    }

    @Test
    public void checkSameWeeklyScheduleConflict() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

            defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                    .setFrequency("Weekly")
                    .setHour(8)
                    .setMinute(30)
                    .setPeriodOfDay("PM")
                    .setDay("Sunday")
                    .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", defectTrackerSchedulePage.isNewSchedulePresent("Sunday_8_30_PM"));

        defectTrackerSchedulePage.clickOrganizationHeaderLink()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency("Weekly")
                .setHour(8)
                .setMinute(30)
                .setPeriodOfDay("PM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        assertTrue("Same Schedule was Created",
                defectTrackerSchedulePage.isErrorPresent("Another defect tracker update is scheduled at that time/frequency"));
    }

    @Test
    public void DeleteDailyDefectTrackerScheduling() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency("Daily")
                .setHour(7)
                .setMinute(15)
                .setPeriodOfDay("PM")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", defectTrackerSchedulePage.isNewSchedulePresent("_7_15_PM"));

        defectTrackerSchedulePage.clickDeleteDefectTrackerButton("_7_15_PM");

        assertFalse("The Schedule wasn't Deleted",
                defectTrackerSchedulePage.isDeleteButtonPresent("_7_15_PM"));
    }

    @Test
    public void DeleteweeklyDefectTrackerScheduling() {

        DefectTrackerSchedulePage defectTrackerSchedulePage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency("Weekly")
                .setHour(11)
                .setMinute(30)
                .setPeriodOfDay("AM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created",
                defectTrackerSchedulePage.isNewSchedulePresent("Sunday_11_30_AM"));

        defectTrackerSchedulePage.clickDeleteDefectTrackerButton("Sunday_11_30_AM");

        assertFalse("The Schedule wasn't Deleted",
                defectTrackerSchedulePage.isDeleteButtonPresent("Sunday_11_30_AM"));
    }

    @Test
    public void defectTrackerNameValidation() {
        String defectTrackerName = getName();
        String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

        defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker()
                .clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTrackerErrorExpected();

        System.out.print(driver.findElement(By.id("nameServerError")).getText());
        assertTrue("No error message displayed", driver.findElement(By.id("nameServerError"))
                .getText().equals("That name is already taken."));
    }
}
