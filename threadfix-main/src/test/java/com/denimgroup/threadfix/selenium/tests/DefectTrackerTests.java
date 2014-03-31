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

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DefectTrackerTests extends BaseTest {

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
    private static final String TFS_PROJECTNAME = ("Vulnerability Manager Demo");

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
	public void testCreateDefectTracker() {
		String newDefectTrackerName = "testCreateDefectTracker"+ getRandomString(3);
		String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
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

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
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

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
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

        String testLongInput = longInput.substring(0, DefectTracker.NAME_LENGTH);

		// Test browser length limit
		defectTrackerIndexPage = defectTrackerIndexPage.enterName(null,longInput)
                .enterURL(null, TEST_BUGZILLA_URL)
                .clickSaveNewDefectTracker();

		assertTrue("The Defect Tracker name was not cropped correctly.",
				defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(testLongInput));

		// Test name duplication checking
		String orgName = testLongInput;

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

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password")
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
	public void testEditDefectTrackerFieldValidation() {                            //this one!!!!!!!!!!
        String emptyString = "";
        String whiteSpaceString = "           ";

		String newDefectTrackerName = "testEditDefectTracker";
		String defectTrackerNameDuplicateTest = "testEditDefectTracker-edit";

		String defectTrackerType = "Bugzilla";

		String emptyInputError = "This field cannot be blank";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
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
                .clickOrganizationHeaderLink()
                .clickDefectTrackersLink()
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

        String testLongInput = longInput.substring(0, DefectTracker.NAME_LENGTH);

        assertTrue("The Defect Tracker name was not cropped correctly.",
                defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(testLongInput));

        newDefectTrackerName = testLongInput;

		// Test name duplication checking
		defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink()
                .clickEditLink(newDefectTrackerName)
                .enterName(newDefectTrackerName, defectTrackerNameDuplicateTest)
                .clickUpdateDefectTrackerButtonInvalid();
		assertTrue(defectTrackerIndexPage.getNameErrorsText().equals("That name is already taken."));
	}

//	@Test
//	public void TFSCreate() {
//		String newDefectTrackerName = "tfsCreate" + getRandomString(3);
//		String defectTrackerURL = "https://tfs.denimgroup.com:8080";
//		String defectTrackerType = "Microsoft TFS";
//
//        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password")
//                .clickDefectTrackersLink();
//
//		defectTrackerIndexPage = defectTrackerIndexPage
//				.clickAddDefectTrackerButton()
//                .enterName(null,newDefectTrackerName)
//                .enterType(null, defectTrackerType)
//                .enterURL(null, defectTrackerURL)
//                .clickSaveNewDefectTracker();
//
//		assertTrue("DefectTracker Page did not create a TFS tracker correctly.",
//				defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(newDefectTrackerName));
//	}

//	@Test
//	public void TFSEdit() {
//		String defectTrackerName = "editTFSDefectTracker" + getRandomString(3);
//        String replacementName = "replacementDefectTracker" + getRandomString(3);
//		String defectTrackerURL = "https://tfs.denimgroup.com:8080";
//		String defectTrackerType = "Microsoft TFS";
//
//        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password")
//                .clickDefectTrackersLink();
//
//		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
//                .enterName(null, defectTrackerName)
//                .enterType(null, defectTrackerType)
//                .enterURL(null, defectTrackerURL)
//                .clickSaveNewDefectTracker();
//
//		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(defectTrackerName)
//                .enterName(defectTrackerName,replacementName)
//                .clickUpdateDefectTrackerButton();
//
//		assertTrue("DefectTracker Page did not edit TFS tracker correctly.",
//				defectTrackerIndexPage.doesNameExist(replacementName));
//	}

    @Test
    public void jiraCreate() {
        String defectTrackerName = "jiraCreate"+ getRandomString(3);
        String defectTrackerType = "Jira";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null,defectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null,TEST_JIRA_URL)
                .clickSaveNewDefectTracker();

        assertTrue("DefectTracker Page did not create correctly.",
                defectTrackerIndexPage.isTextPresentInDefectTrackerTableBody(defectTrackerName));
    }

	@Test
	public void jiraEdit() {
		String defectTrackerName = "jiraEdit" + getRandomString(3);
        String replacementName = "jiraEditNew" + getRandomString(3);
		String defectTrackerType = "Jira";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, defectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, TEST_JIRA_URL)
                .clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(defectTrackerName)
                .enterName(defectTrackerName, replacementName)
                .clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker page did not edit jira tracker correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));
	}

    @Test
    public void bugzillaCreate() {
        String defectTrackerName = "testEditDefectTracker" + getRandomString(3);
        String defectTrackerUrl = "http://10.2.10.145/bugzilla/";
        String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password")
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
		String defectTrackerName = "bugzillaEdit" + getRandomString(3);
        String replacementName = "bugzillaEditNew" + getRandomString(3);
		String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage= defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, defectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, "http://10.2.10.145/bugzilla/")
                .clickSaveNewDefectTracker();

		defectTrackerIndexPage = defectTrackerIndexPage.clickEditLink(defectTrackerName)
                .enterName(defectTrackerName, replacementName)
                .clickUpdateDefectTrackerButton();

		assertTrue("DefectTracker page did not edit bugzilla tracker correctly.",
				defectTrackerIndexPage.doesNameExist(replacementName));
	}

	@Test
	public void testAttachToAppBugzillaTracker() {
		String defectTrackerName = "attachAppBugzilla" + getRandomString(3);
		String defectTrackerType = "Bugzilla";
		String teamName = "bugzillaAttachTestTeam" + getRandomString(3);
		String appName = "bugzillaAttachTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password")
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, defectTrackerName)
                .enterType(null, defectTrackerType)
                .enterURL(null, BUGZILLA_URL)
                .clickSaveNewDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(defectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
	}

//	@Test
//	public void testAttachToAppTFSTracker() {
//		String defectTrackerName = "attachAppTFS" + getRandomString(3);
//		String defectTrackerType = "Microsoft TFS";
//		String teamName = "tfsAttachTestTeam" + getRandomString(3);
//		String appName = "tfsAttachTestApp" + getRandomString(3);
//
//        DatabaseUtils.createTeam(teamName);
//        DatabaseUtils.createApplication(teamName, appName);
//
//        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user", "password")
//                .clickDefectTrackersLink();
//
//		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
//                .enterName(null, defectTrackerName)
//                .enterType(null, defectTrackerType)
//                .enterURL(null, TFS_URL)
//                .clickSaveNewDefectTracker();
//
//        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
//				.expandTeamRowByName(teamName)
//				.clickViewAppLink(appName, teamName)
//				.addDefectTracker(defectTrackerName, TFS_USERNAME, TFS_PASSWORD, TFS_PROJECTNAME);
//
//		assertTrue("Defect tracker wasn't attached correctly",
//                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
//	}

	@Test
	public void testAttachToAppJiraTracker() {
		String newDefectTrackerName = "attachAppJira" + getRandomString(3);
		String type = "Jira";
		String teamName = "jIRAAttachTestTeam" + getRandomString(3);
		String appName = "JIRAAttachTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

		defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null, newDefectTrackerName)
                .enterType(null, type)
                .enterURL(null, JIRA_URL)
                .clickSaveNewDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName)
				.addDefectTracker(newDefectTrackerName, JIRA_USERNAME, JIRA_PASSWORD, JIRAPROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
	}

	@Test
	public void testSwitchDefectTrackers() {
		String defectTracker1 = "testSwitchDefectTracker1" + getRandomString(3);
		String defectTracker2 = "testSwitchDefectTracker2" + getRandomString(3);
		String defectTrackerType = "Bugzilla";

		String teamName = "bugzillaAAttachTestTeam" + getRandomString(3);
		String appName = "bugzillaAttachTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login("user","password")
                .clickDefectTrackersLink();

        defectTrackerIndexPage = defectTrackerIndexPage.clickAddDefectTrackerButton()
                .enterName(null,defectTracker1)
                .enterType(null, defectTrackerType)
                .enterURL(null, BUGZILLA_URL)
                .clickSaveNewDefectTracker();

        defectTrackerIndexPage = defectTrackerIndexPage.clickDefectTrackersLink()
                .clickAddDefectTrackerButton()
                .enterName(null,defectTracker2)
                .enterType(null, defectTrackerType)
                .enterURL(null, BUGZILLA_URL)
                .clickSaveNewDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .addDefectTracker(defectTracker1, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);
		
		assertTrue("Defect tracker wasn't attached correctly",
                applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
		
		applicationDetailPage = applicationDetailPage.clickCloseAppModal();

		sleep(2000);
		applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .editDefectTracker(defectTracker2, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);

		assertTrue("Defect tracker wasn't attached correctly",
				applicationDetailPage.clickEditDeleteBtn().isDefectTrackerAttached());
	}
}
