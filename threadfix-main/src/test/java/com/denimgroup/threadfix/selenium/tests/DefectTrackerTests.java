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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;

import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;


public class DefectTrackerTests extends BaseTest {

    private DefectTrackerIndexPage defectTrackerIndexPage;
    private ApplicationDetailPage applicationDetailPage;

	private static final String TEST_BUGZILLA_URL = DefectTrackerIndexPage.DT_URL;
	private static final String TEST_JIRA_URL = DefectTrackerIndexPage.JIRA_URL;
    private static final String JIRA_USERNAME = System.getProperty("JIRA_USERNAME");
    private static final String JIRA_PASSWORD = System.getProperty("JIRA_PASSWORD");
    private static final String JIRA_URL = System.getProperty("JIRA_URL");
    private static final String JIRAPROJECTNAME = System.getProperty("JIRAPROJECTNAME");
    private static final String BUGZILLA_USERNAME = System.getProperty("BUGZILLA_USERNAME");
    private static final String BUGZILLA_PASSWORD = System.getProperty("BUGZILLA_PASSWORD");
    private static final String BUGZILLA_URL = System.getProperty("BUGZILLA_URL");
    private static final String BUGZILLAPROJECTNAME = "For ThreadFix";
    private static final String TFS_USERNAME = System.getProperty("TFS_USERNAME");
    private static final String TFS_PASSWORD = System.getProperty("TFS_PASSWORD");
    private static final String TFS_URL = System.getProperty("TFS_URL");
    private static final String TFS_PROJECTNAME = System.getProperty("TFS_PROJECTNAME");

	String longInput = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			+ "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    static {
        if (TEST_BUGZILLA_URL == null) {
            throw new RuntimeException("Please set TEST_BUGZILLA_URL property");
        }
        if (TEST_JIRA_URL == null){
            throw new RuntimeException("Please set TEST_JIRA_URL property.");
        }
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
        if (BUGZILLAPROJECTNAME == null){
            throw new RuntimeException("Please set BUGZILLAPROJECTNAME property.");
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
        if (TFS_PROJECTNAME == null){
            throw new RuntimeException("Please set TFS_PROJECTNAME property.");
        }
    }

    @Test
	public void testCreateDefectTracker() {
		String newDefectTrackerName = "testCreateDefectTracker"+ getRandomString(3);
		String defectTrackerType = "Bugzilla";

		defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

		defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, newDefectTrackerName)
				.enterType(null, defectTrackerType).enterURL(null, TEST_BUGZILLA_URL)
                .clickSaveNewDefectTracker();

		assertTrue("The defectTracker was not present in the table.",
				defectTrackerIndexPage.doesNameExist(newDefectTrackerName));
	}

    @Test
    public void testDeleteDefectTracker() {
        String newDefectTrackerName = "testDeleteDefectTracker"+ getRandomString(3);
        String defectTrackerType = "Bugzilla";

        defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink()
                .clickAddDefectTrackerButton()
                .enterName(null, newDefectTrackerName).enterType(null, defectTrackerType)
                .enterURL(null, TEST_BUGZILLA_URL)
                .clickSaveNewDefectTracker();

        defectTrackerIndexPage = defectTrackerIndexPage.clickDeleteButton(newDefectTrackerName)
                .clickDefectTrackersLink();

        assertFalse("The defectTracker was still present after attempted deletion.",
                defectTrackerIndexPage.doesNameExist(newDefectTrackerName));
    }

	@Test
	public void testCreateDefectTrackerFieldValidation() {
		String emptyString = "";
		String whiteSpaceString = "           ";
		String urlFormatString = "asdfwe";

		String emptyInputError = "This field cannot be blank";
		String urlError = "Not a valid URL";

		defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink()
                .clickAddDefectTrackerButton();

		//Test empty and whitespace input
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null, emptyString)
                .enterURL(null, emptyString)
				.clickAddDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present",
                emptyInputError.equals(defectTrackerIndexPage.getNameErrorsText()));
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage.getUrlErrorsText()));

		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null, whiteSpaceString)
				.enterURL(null, whiteSpaceString)
				.clickAddDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present",
				emptyInputError.equals(defectTrackerIndexPage.getNameErrorsText()));
		assertTrue("The correct error text was not present",
				urlError.equals(defectTrackerIndexPage.getUrlErrorsText()));

		// Test URL format checking
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null, "normal name")
                .enterURL(null, urlFormatString)
				.clickAddDefectTrackerButtonInvalid();
		assertTrue("The URL format check error text was not present.",
				defectTrackerIndexPage.getUrlErrorsText().equals(urlError));

		// Test url validation
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null, longInput)
				.enterURL(null, "http://" + longInput)
				.clickAddDefectTrackerButtonInvalid();
		assertTrue("The Defect Tracker URL was not validated correctly.",
				defectTrackerIndexPage.getUrlErrorsText().equals("URL is invalid."));

		// Test browser length limit
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null,
				longInput).enterURL(null, TEST_BUGZILLA_URL)
                .clickSaveNewDefectTracker();

		// might need to change the row number that this is checking
		assertTrue("The Defect Tracker name was not cropped correctly.",
				defectTrackerIndexPage.getDefectTrackerName(1).length() == DefectTracker.NAME_LENGTH);

		// Test name duplication checking
		String orgName = defectTrackerIndexPage.getDefectTrackerName(1);

		defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink()
                .clickAddDefectTrackerButton()
                .enterName(null, orgName).enterURL(null, TEST_BUGZILLA_URL)
				.clickAddDefectTrackerButtonInvalid();

		assertTrue(defectTrackerIndexPage.getNameErrorsText().equals(
				"That name is already taken."));
	}

	@Test
	public void testEditDefectTrackerName() {
		String originalDefectTrackerName = "testEditDefectTracker"+ getRandomString(3);
		String editedDefectTrackerName = "testEditDefectTracker-edit"+ getRandomString(3);
		String originalDefectTrackerType = "Jira";
        String editedDefectTrackerType = "Bugzilla";

		defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, originalDefectTrackerName)
                .enterType(null, originalDefectTrackerType)
				.enterURL(null, TEST_JIRA_URL)
                .clickSaveNewDefectTracker();

        //Edit previously created defect tracker
		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(originalDefectTrackerName)
                .enterName(originalDefectTrackerName, editedDefectTrackerName)
                .enterType(originalDefectTrackerName, editedDefectTrackerType)
                .enterURL(originalDefectTrackerName, TEST_BUGZILLA_URL)
                .clickUpdateDefectTrackerButton();

		assertTrue("Edit did not change the name.",
                defectTrackerIndexPage.doesNameExist(editedDefectTrackerName));
        assertTrue("Edit did not change the type.",
                defectTrackerIndexPage.doesTypeExistForName(editedDefectTrackerName, editedDefectTrackerType));
        assertTrue("Edit did not change url.",
                defectTrackerIndexPage.doesURLExistForName(editedDefectTrackerName, TEST_BUGZILLA_URL));
	}

	@Test
	public void testEditDefectTrackerFieldValidation() {
        String emptyString = "";
        String whiteSpaceString = "           ";

		String newDefectTrackerName = "testEditDefectTracker";
		String defectTrackerNameDuplicateTest = "testEditDefectTracker-edit";

		String defectTrackerType = "Bugzilla";

		String emptyInputError = "This field cannot be blank";

		defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, defectTrackerNameDuplicateTest)
                .enterType(null, defectTrackerType)
                .enterURL(null, TEST_BUGZILLA_URL)
                .clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
				.enterName(null, newDefectTrackerName)
                .enterType(null, defectTrackerType)
				.enterURL(null, TEST_BUGZILLA_URL)
				.clickSaveNewDefectTracker()
                .clickEditLink(newDefectTrackerName);

		// Test empty and whitespace input
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(newDefectTrackerName,emptyString)
                .clickUpdateDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present",
                emptyInputError.equals(defectTrackerIndexPage.getNameErrorsText()));
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(newDefectTrackerName, whiteSpaceString)
                .clickUpdateDefectTrackerButtonInvalid();
		assertTrue("The correct error text was not present",
                emptyInputError.equals(defectTrackerIndexPage.getNameErrorsText()));

		// Test browser length limit
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(newDefectTrackerName, longInput)
				               .clickUpdateDefectTrackerButton();
		newDefectTrackerName = defectTrackerIndexPage.getNameText(1);
		assertTrue("The defectTracker name was not cropped correctly.",
                defectTrackerIndexPage.getNameText(1).length() == DefectTracker.NAME_LENGTH);

		// Test name duplication checking
		defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink()
                .clickEditLink(newDefectTrackerName)
                .enterName(newDefectTrackerName, defectTrackerNameDuplicateTest)
                .clickUpdateDefectTrackerButtonInvalid();
		assertTrue(defectTrackerIndexPage.getNameErrorsText().equals("That name is already taken."));
	}

	@Test
	public void TFSCreate() {
		String newDefectTrackerName = "tfsCreate" + getRandomString(3);
		String defectTrackerURL = "https://tfs.denimgroup.com:8080";
		String defectTrackerType = "Microsoft TFS";

		defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage
				.clickAddDefectTrackerButton()
                .enterName(null,newDefectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, defectTrackerURL)
                .clickSaveNewDefectTracker();

		assertTrue("DefectTracker Page did not create a TFS tracker correctly.",
				defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
	}

	@Test
	public void TFSEdit() {
		String newDefectTrackerName = "editTFSDefectTracker" + getRandomString(3);
        String replacementName = "replacementDefectTracker" + getRandomString(3);
		String defectTrackerURL = "https://tfs.denimgroup.com:8080";
		String defectTrackerType = "Microsoft TFS";

		defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .setNameInput(newDefectTrackerName)
                .setDefectTrackerTypeSelect(defectTrackerType)
                .setUrlInput(defectTrackerURL)
                .clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(newDefectTrackerName)
                .clickUpdateDefectTrackerButton()
                .clickDefectTrackersLink()
                .clickEditLink(newDefectTrackerName)
                .enterName(newDefectTrackerName,replacementName)
                .clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker Page did not edit TFS tracker correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));
	}

    @Test
    public void jiraCreate() {
        String newDefectTrackerName = "jiraCreate"+ getRandomString(3);
        String defectTrackerType = "Jira";

        defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null,newDefectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null,TEST_JIRA_URL)
                .clickSaveNewDefectTracker();

        assertTrue("DefectTracker Page did not create correctly.",
                defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
    }

	@Test
	public void jiraEdit() {
		String newDefectTrackerName = "jiraEdit" + getRandomString(3);
        String replacementName = "jiraEditNew" + getRandomString(3);
		String defectTrackerType = "Jira";

		defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, newDefectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, TEST_JIRA_URL)
                .clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(newDefectTrackerName)
                .enterName(newDefectTrackerName, replacementName)
                .clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker page did not edit jira tracker correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));
	}

    @Test
    public void bugzillaCreate() {
        String defectTrackerName = "testEditDefectTracker" + getRandomString(3);
        String defectTrackerUrl = "http://10.2.10.145/bugzilla/";
        String defectTrackerType = "Bugzilla";

        defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, defectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, defectTrackerUrl)
                .clickSaveNewDefectTracker();

        assertTrue("DefectTracker Page did not create correctly.",
                defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(defectTrackerName));
    }

	@Test
	public void bugzillaEdit() {
		String newDefectTrackerName = "bugzillaEdit" + getRandomString(3);
        String replacementName = "bugzillaEditNew" + getRandomString(3);
		String defectTrackerType = "Bugzilla";

		defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage= defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, newDefectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, "http://10.2.10.145/bugzilla/")
                .clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(newDefectTrackerName)
                .enterName(newDefectTrackerName, replacementName)
                .clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker page did not edit bugzilla tracker correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));
	}

	@Test
	public void testAttachToAppBugzillaTracker() {
		assertFalse("BUGZILLA_PASSWORD is not assigned from system properties", BUGZILLA_PASSWORD == null);
		assertFalse("BUGZILLA_USERNAME is not assigned from system properties", BUGZILLA_USERNAME == null);
		assertFalse("BUGZILLA_URL is not assigned from system properties", BUGZILLA_URL == null);
		assertFalse("BUGZILLAPROJECTNAME is not assigned from system properties", BUGZILLAPROJECTNAME == null);

		String defectTrackerName = "attachAppBugzilla" + getRandomString(3);
		String defectTrackerType = "Bugzilla";
		String teamName = "bugzillaAttachTestTeam" + getRandomString(3);
		String appName = "bugzillaAttachTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

		defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, defectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, BUGZILLA_URL)
                .clickSaveNewDefectTracker();

		applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(defectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
	}

	@Test
	public void testAttachToAppTFSTracker() {
		assertFalse("TFS_PASSWORD is not assigned from system properties", TFS_PASSWORD == null);
		assertFalse("TFS_USERNAME is not assigned from system properties", TFS_USERNAME == null);
		assertFalse("BUGZILLA_URL is not assigned from system properties", TFS_URL == null);
		assertFalse("TFS_PROJECTNAME is not assigned from system properties", TFS_PROJECTNAME == null);

		String defectTrackerName = "attachAppTFS" + getRandomString(3);
		String defectTrackerType = "Microsoft TFS";
		String teamName = "bugzillaAttachTestTeam" + getRandomString(3);
		String appName = "bugzillaAttachTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

		defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, defectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, TFS_URL)
                .clickSaveNewDefectTracker();

		applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(defectTrackerName, TFS_USERNAME, TFS_PASSWORD, TFS_PROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
	}

	@Test
	public void testAttachToAppJiraTracker() {
		assertFalse("JIRA_PASSWORD is not assigned from system properties", JIRA_PASSWORD == null);
		assertFalse("JIRA_USERNAME is not assigned from system properties", JIRA_USERNAME == null);
		assertFalse("JIRA_URL is not assigned from system properties", JIRA_URL == null);
		assertFalse("JIRAPROJECTNAME is not assigned from system properties", JIRAPROJECTNAME == null);

		String newDefectTrackerName = "attachAppJira" + getRandomString(3);
		String type = "Jira";
		String teamName = "jIRAAttachTestTeam" + getRandomString(3);
		String appName = "JIRAAttachTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

		defectTrackerIndexPage = loginPage.login("user",
				"password").clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, newDefectTrackerName)
                .enterType(null, type)
                .enterURL(null, JIRA_URL)
                .clickSaveNewDefectTracker();

		applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(newDefectTrackerName, JIRA_USERNAME, JIRA_PASSWORD, JIRAPROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
	}

	@Test
	public void testSwitchDefectTrackers() {
		assertFalse("JIRA_PASSWORD is not assigned from system properties",JIRA_PASSWORD == null);
		assertFalse("JIRA_USERNAME is not assigned from system properties",JIRA_USERNAME == null);
		assertFalse("JIRA_URL is not assigned from system properties",JIRA_URL == null);
		assertFalse("JIRAPROJECTNAME is not assigned from system properties",JIRAPROJECTNAME == null);

		String defectTracker1 = "testSwitchDefectTracker1" + getRandomString(3);
		String defectTracker2 = "testSwitchDefectTracker2" + getRandomString(3);
		String defectTrackerType = "Jira";

		String teamName = "jIRAAttachTestTeam" + getRandomString(3);
		String appName = "JIRAAttachTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

		defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null,defectTracker1)
                .enterType(null, defectTrackerType)
                .enterURL(null, JIRA_URL)
                .clickSaveNewDefectTracker()
                .clickAddDefectTrackerButton()
                .enterName(null,defectTracker2)
                .enterType(null, defectTrackerType)
                .enterURL(null, JIRA_URL)
                .clickSaveNewDefectTracker();
		
		applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .addDefectTracker(defectTracker1, JIRA_USERNAME,JIRA_PASSWORD, JIRAPROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
		
		applicationDetailPage = applicationDetailPage.clickCloseAppModal();

		sleep(2000);
		applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .editDefectTracker(defectTracker2, JIRA_USERNAME, JIRA_PASSWORD, JIRAPROJECTNAME);

		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
	}
}
