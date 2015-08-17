////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class DefectTrackerIT extends BaseDataTest {
    private DefectTrackerIndexPage defectTrackerIndexPage;

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

    @Before
    public void initialNavigation(){
        defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink();

    }

    //===========================================================================================================
    // Creation, Deletion, and Editing
    //===========================================================================================================

    @Test
    public void testCheckDefectTrackerPage() {
        assertTrue("Defect Tracker page wasn't shown", defectTrackerIndexPage.isCreateNewTrackerButtonPresent());
    }

    @Test
	public void testCreateDefectTracker() {
		String newDefectTrackerName = getName();
		String defectTrackerType = "Bugzilla";

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
    public void testDeleteDefectTracker() {
        String newDefectTrackerName = getName();
        String defectTrackerType = "Bugzilla";

        defectTrackerIndexPage.clickAddDefectTrackerButton()
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
    public void testEditDefectTracker() {
        String originalDefectTrackerName = getName();
        String editedDefectTrackerName = getName();
        String originalDefectTrackerType = "Jira";
        String editedDefectTrackerType = "Bugzilla";

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
    public void testDeleteAddDefectTrackerWithSameName() {
        String defectTrackerName = getName();
        String defectTrackerType = "Bugzilla";

        defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        defectTrackerIndexPage.clickEditLink(defectTrackerName)
                .clickDeleteButton();

        defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        assertTrue("Defect tracker was not present in table.", defectTrackerIndexPage.isNamePresent(defectTrackerName));
    }

    //TODO after HP quality Center machine comes up
    @Ignore
    @Test
    public void testEditDefectTrackerFromJiraToHP() {
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
    public void testCheckDefectTrackerPresentAfterEditing() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String defectTrackerName = getName();
        String replacementName = getName();
        String defectTrackerType = "Bugzilla";

        defectTrackerIndexPage.refreshPage();

        defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setURL(BUGZILLA_URL)
                .setType(defectTrackerType)
                .clickSaveDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .addDefectTracker(defectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME);

        assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());

        applicationDetailPage.clickCloseModalButton();

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

    @Test
    public void testSwitchDefectTrackers() {
        String defectTracker1 = getName();
        String defectTracker2 = getName();
        String defectTrackerType = "Bugzilla";

        String teamName = createTeam();
        String appName = createApplication(teamName);

        defectTrackerIndexPage.refreshPage();

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
                .addDefectTracker(defectTracker1, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME);

        assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
        //assertTrue("Defect Tracker wasn't attached correctly",applicationDetailPage.getDefectTrackerName().contains(defectTracker1));

        applicationDetailPage = applicationDetailPage.clickModalCancel();
        sleep(500);
        applicationDetailPage.addDefectTracker(defectTracker2, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME);

        assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
        //assertTrue("Defect Tracker wasn't attached correctly",applicationDetailPage.getDefectTrackerName().contains(defectTracker2));
    }

    //===========================================================================================================
    // Validation
    //===========================================================================================================

	@Test
	public void testCreateDefectTrackerFieldValidation() {
		String emptyString = "";
		String whiteSpaceString = "           ";
		String urlFormatString = "asdfwe";

        defectTrackerIndexPage.clickAddDefectTrackerButton();

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
    public void testLongNameFormat() {
        String longName = getRandomString(60);
        String longNameFormatted = longName.substring(0,49);

        defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(longName)
                .setURL(BUGZILLA_URL)
                .setType("Bugzilla")
                .clickSaveDefectTracker();

        assertTrue("Success message error.",
                defectTrackerIndexPage.getSuccessMessage().contains("Successfully created defect tracker " + longNameFormatted));

        assertTrue("The defectTracker was not present in the table.",
                defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(longNameFormatted));
    }

    @Test
	public void testEditDefectTrackerFieldValidation() {
        String emptyString = "";
        String whiteSpaceString = "           ";

		String newDefectTrackerName = getName();
		String defectTrackerNameDuplicateTest = getName();

		String defectTrackerType = "Bugzilla";
        String longInput = getRandomString(55);

        defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerNameDuplicateTest)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        defectTrackerIndexPage.refreshPage();

		defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(newDefectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        defectTrackerIndexPage.refreshPage();

        defectTrackerIndexPage.clickEditLink(newDefectTrackerName);

		// Test empty and whitespace input
		defectTrackerIndexPage.setName(emptyString)
                .clickModalSubmitInvalid();
        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameRequiredError"));
		assertTrue("The correct error text was not present",defectTrackerIndexPage.getNameRequiredErrorsText().contains("Name is required."));

		defectTrackerIndexPage.setName(whiteSpaceString)
                .clickModalSubmitInvalid();
        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameRequiredError"));
		assertTrue("The correct error text was not present",defectTrackerIndexPage.getNameRequiredErrorsText().contains("Name is required."));

		// Test browser length limit
		defectTrackerIndexPage.setName(longInput)
                .clickModalSubmitInvalid();
        assertTrue("Error message was not visible.",defectTrackerIndexPage.isElementVisible("nameCharacterLimitError"));

        defectTrackerIndexPage.clickModalCancel();
        defectTrackerIndexPage.refreshPage();

		// Test name duplication checking
		defectTrackerIndexPage.clickDefectTrackersLink()
                .clickEditLink(newDefectTrackerName)
                .setName(defectTrackerNameDuplicateTest)
                .clickModalSubmitInvalid();
        assertTrue("Error message was not visible.",defectTrackerIndexPage.isErrorPresent("nameServerError"));
        assertTrue("The correct error text was not present",defectTrackerIndexPage.getNameDuplicateErrorsText().contains("That name is already taken."));
	}


    //===========================================================================================================
    // JIRA
    //===========================================================================================================

	@Test
	public void testJiraEdit() {
		String defectTrackerName = getName();
        String replacementName = getName();
		String defectTrackerType = "Jira";

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

    //===========================================================================================================
    // Bugzilla
    //===========================================================================================================

	@Test
	public void testBugzillaEdit() {
		String defectTrackerName = getName();
        String replacementName = getName();
		String defectTrackerType = "Bugzilla";

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
    public void testAttachBugzillaTracker() {
        String defectTrackerName = getName();
        String defectTrackerType = "Bugzilla";
        String teamName = getName();
        String appName = getName();

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        defectTrackerIndexPage.refreshPage();

        defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .addDefectTracker(defectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME);

        assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
    }

    @Test
    public void testDeleteAttachedBugzillaTracker() {
        String defectTrackerName = getName();
        String defectTrackerType = "Bugzilla";

        String teamName = createTeam();
        String appName = createApplication(teamName);

        defectTrackerIndexPage.refreshPage();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setType(defectTrackerType)
                .setURL(BUGZILLA_URL)
                .clickSaveDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .addDefectTracker(defectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME);

        defectTrackerIndexPage = applicationDetailPage.clickDefectTrackersLink()
                .clickEditLink(defectTrackerName)
                .clickDeleteButton()
                .clickDefectTrackersLink();

        assertFalse("The defectTracker was still present after attempted deletion.",
                defectTrackerIndexPage.isElementPresent("defectTackerName" + defectTrackerName));
    }

    //===========================================================================================================
    // Scheduling
    //===========================================================================================================

    @Test
    public void testDefectTrackerDailyScheduling() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = defectTrackerIndexPage.clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency("Daily")
                .setHour(1)
                .setMinute(15)
                .setPeriodOfDay("PM")
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", defectTrackerSchedulePage.isNewSchedulePresent("_1_15_PM"));
    }

    @Test
    public void testDefectTrackerWeeklyScheduling() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = defectTrackerIndexPage.clickScheduleUpdateTab();

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
    public void testCheckSameDailyScheduleConflict() {
        String frequency = "Daily";
        int hour = 9;
        int minutes = 30;
        String periodOfDay = "AM";

        DefectTrackerSchedulePage defectTrackerSchedulePage = defectTrackerIndexPage.clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency(frequency)
                .setHour(hour)
                .setMinute(minutes)
                .setPeriodOfDay(periodOfDay)
                .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", defectTrackerSchedulePage.isNewSchedulePresent("_9_30_AM"));

        defectTrackerSchedulePage.clickDashboardLink()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency(frequency)
                .setHour(hour)
                .setMinute(minutes)
                .setPeriodOfDay(periodOfDay)
                .clickAddScheduledUpdated();

        defectTrackerSchedulePage.waitForErrorMessage();

        assertTrue("Same Schedule was Created",
                defectTrackerSchedulePage.isErrorPresent("Another defect tracker update is scheduled at that time/frequency"));
    }

    @Test
    public void testCheckSameWeeklyScheduleConflict() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = defectTrackerIndexPage.clickScheduleUpdateTab();

            defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                    .setFrequency("Weekly")
                    .setHour(8)
                    .setMinute(30)
                    .setPeriodOfDay("PM")
                    .setDay("Sunday")
                    .clickAddScheduledUpdated();

        assertTrue("New Schedule wasn't Created", defectTrackerSchedulePage.isNewSchedulePresent("Sunday_8_30_PM"));

        defectTrackerSchedulePage.clickDashboardLink()
                .clickDefectTrackersLink()
                .clickScheduleUpdateTab();

        defectTrackerSchedulePage.clickScheduleNewUpdateTab()
                .setFrequency("Weekly")
                .setHour(8)
                .setMinute(30)
                .setPeriodOfDay("PM")
                .setDay("Sunday")
                .clickAddScheduledUpdated();

        defectTrackerSchedulePage.waitForErrorMessage();

        assertTrue("Same Schedule was Created",
                defectTrackerSchedulePage.isErrorPresent("Another defect tracker update is scheduled at that time/frequency"));
    }

    @Test
    public void testDeleteDailyDefectTrackerScheduling() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = defectTrackerIndexPage.clickScheduleUpdateTab();

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
    public void testDeleteWeeklyDefectTrackerScheduling() {
        DefectTrackerSchedulePage defectTrackerSchedulePage = defectTrackerIndexPage.clickScheduleUpdateTab();

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
}
