package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class VulnTests extends BaseTest {

	private String teamName = getRandomString(8);
	private String appName = getRandomString(8);
	private String defectTrackerName = getRandomString(8);
    private ApplicationDetailPage applicationDetailPage;

	private final static int JIRA = 0;
	private final static int BUG = 1;
	private final static int TFS = 2;
	
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
	private static final String TFS_PROJECTNAME = "Vulnerability Manager Demo";
    private static final String API_KEY = System.getProperty("API_KEY");
    private static final String REST_URL = System.getProperty("REST_URL");


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
        if (API_KEY == null) {
            throw new RuntimeException("Please set API_KEY in run configuration.");
        }
        if (REST_URL == null) {
            throw new RuntimeException("Please set REST_URL in run configuration.");
        }
    }
	
	@Test
	public void mergeSingleVulnJira(){
        int boxNumber = 1;
		assertTrue("Jira",build(JIRA));
		//merge here
		//nav to app detail page

		//submit merge
		applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(boxNumber)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-190")
				.clickMergeDefectSubmit();
		
		//verify
        applicationDetailPage.clickExpandAllVulns();
		
		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 1);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void mergeSingleVulnBugzilla(){
		assertTrue("bug",build(BUG));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();

		//verify
        applicationDetailPage.clickExpandAllVulns();


		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 1);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void mergeSingleVulnTFS(){
		assertTrue("bug",build(TFS));

        //submit merge
        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
                .clickMergeDefectLink()
                .selectMergeDefect("793")
                .clickMergeDefectSubmit();

        //verify
        applicationDetailPage.clickExpandAllVulns();

        assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 1);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}
	
	@Test
	public void mergeMultiVulnJira(){
		assertTrue("Jira",build(JIRA));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-185")
				.clickMergeDefectSubmit();

		//verify
		applicationDetailPage.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 3);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void mergeMultiVulnBugzilla(){
		assertTrue("bug",build(BUG));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();

		//verify
        applicationDetailPage.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 3);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void mergeMultiVulnTFS(){
		assertTrue("bug",build(TFS));

        //submit merge
        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
                .clickVulnCheckBox(2)
                .clickVulnCheckBox(3)
                .clickMergeDefectLink()
                .selectMergeDefect("793")
                .clickMergeDefectSubmit();

        //verify
        applicationDetailPage.clickExpandAllVulns();

        assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 3);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}
	
	@Test
	public void changeMergeSingleVulnJira(){
		assertTrue("Jira",build(JIRA));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-175")
				.clickMergeDefectSubmit();

		//change merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-176")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 1);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void changeMergeSingleVulnBugzilla(){
		assertTrue("bug",build(BUG));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();

		//change merge
        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("4")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 1);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void changeMergeSingleVulnTFS(){
		assertTrue("bug",build(TFS));

        //submit merge
        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
                .clickMergeDefectLink()
                .selectMergeDefect("793")
                .clickMergeDefectSubmit();

        //change merge
        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
                .clickMergeDefectLink()
                .selectMergeDefect("826")
                .clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

        assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 1);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}
	
	@Test
	public void changeMergeMultiVulnJira(){
		assertTrue("Jira",build(JIRA));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-193")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-192")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 3);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void changeMergeMultiVulnBugzilla(){
		assertTrue("bug",build(BUG));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("4")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 3);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();

	}

	@Test
	public void changeMergeMultiVulnTFS(){
		assertTrue("bug",build(TFS));

        //submit merge
        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
                .clickVulnCheckBox(2)
                .clickVulnCheckBox(3)
                .clickMergeDefectLink()
                .selectMergeDefect("793")
                .clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
                .clickVulnCheckBox(2)
                .clickVulnCheckBox(3)
                .clickMergeDefectLink()
                .selectMergeDefect("826")
                .clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

        assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 3);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}
	
	@Test
	public void changeMergeMultiDiffVulnJira(){
		assertTrue("Jira",build(JIRA));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-183")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(4)
				.clickVulnCheckBox(5)
				.clickVulnCheckBox(6)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-184")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(4)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-185")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 6);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void changeMergeMultiDiffVulnBugzilla(){
		assertTrue("bug",build(BUG));

		//submit merge
        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(4)
				.clickVulnCheckBox(5)
				.clickVulnCheckBox(6)
				.clickMergeDefectLink()
				.selectMergeDefect("4")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(6)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("3")
				.clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 6);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();

	}

	@Test
	public void changeMergeMultiDiffVulnTFS(){
		assertTrue("bug",build(TFS));

        //submit merge
        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
                .clickVulnCheckBox(2)
                .clickVulnCheckBox(3)
                .clickMergeDefectLink()
                .selectMergeDefect("793")
                .clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(4)
                .clickVulnCheckBox(5)
                .clickVulnCheckBox(6)
                .clickMergeDefectLink()
                .selectMergeDefect("826")
                .clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns()
                .clickVulnCheckBox(1)
                .clickVulnCheckBox(4)
                .clickVulnCheckBox(3)
                .clickMergeDefectLink()
                .selectMergeDefect("860")
                .clickMergeDefectSubmit();

        applicationDetailPage.clickExpandAllVulns();

        assertTrue("Number of submitted vulns is incorrect",applicationDetailPage.getNumOfSubmitedDefects()-1 == 6);

        applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage.logout();
	}

	@Test
	public void submitBlankDefect(){
		assertTrue("blank defect",build(JIRA));

        applicationDetailPage.clickOrganizationHeaderLink()
				.expandTeamRowByIndex(teamName)
				.clickViewAppLink(appName, teamName)
				.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickSubmitDefectLink()
				.submitDefect();

		assertTrue("defect was not submitted", applicationDetailPage.getAlert().contains("The Defect was submitted to the tracker."));
        applicationDetailPage.clickOrganizationHeaderLink();
        applicationDetailPage.logout();

		
	}
	
	private boolean build(int dtType){
		String defectTrackerAppName = "";
		String defectTrackerURL = "";
		String userName = "";
		String password = "";
		String projectName = "";
		String whiteHatAppName = "Demo Site BE";
		String whiteHatKey = System.getProperty("WHITEHAT_KEY");
		switch(dtType){
			case JIRA:
				defectTrackerAppName = "Jira";
				defectTrackerURL = JIRA_URL;
				userName = JIRA_USERNAME;
				password = JIRA_PASSWORD;
				projectName = JIRAPROJECTNAME;
				break;
			case BUG:
				defectTrackerAppName = "Bugzilla";
				defectTrackerURL = BUGZILLA_URL;
				userName = BUGZILLA_USERNAME;
				password = BUGZILLA_PASSWORD;
				projectName = BUGZILLAPROJECTNAME;
				break;
			case TFS:
				defectTrackerAppName = "Microsoft TFS";
				defectTrackerURL = TFS_URL;
				userName = TFS_USERNAME;
				password = TFS_PASSWORD;
				projectName = TFS_PROJECTNAME;
				break;
			default:
				return false;
		}

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));

        TeamIndexPage ti = loginPage.login("user", "password").clickOrganizationHeaderLink();



		//add defect Tracker
		DefectTrackerIndexPage defectTrackerIndexPage = ti.clickDefectTrackersLink()
														  .clickAddDefectTrackerButton()
														  .enterName(null, defectTrackerName)
														  .enterType(null, defectTrackerAppName)
														  .enterURL(null, defectTrackerURL)
														  .clickSaveNewDefectTracker(defectTrackerName);

		//attach defect Tracker
		applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
							   .expandTeamRowByName(teamName)
							   .clickViewAppLink(appName, teamName)
							   .addDefectTracker(defectTrackerName, userName, password, projectName);

		return true;
	}
	



}
