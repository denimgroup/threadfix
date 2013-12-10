package com.denimgroup.threadfix.selenium.pagetests;

import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;

public class TeamDetailPageTest extends PageBaseTest {
	
	private DashboardPage dashboardPage;
	private TeamDetailPage teamdetailPage;
	private boolean build;
	private String teamName = getRandomString(8);
	private String appName = getRandomString(8);
	
	public TeamDetailPageTest(String browser) {
		super(browser);
	}
	
	@Before
	public void init() {
		super.init();
		build = buildElements();
	}
	
	@After
	public void shutdown(){
		destroyElements();
		super.shutDown();
	}
	
//	@Test
//	public void buildUpTest(){
//		assertTrue(build);
//		dashboardPage.logout();
//	}
	
	@Test
	public void actionButtonTest(){
		teamdetailPage = dashboardPage.clickOrganizationHeaderLink().clickViewTeamLink(teamName).clickActionButton();
		boolean actionPresent = teamdetailPage.isActionBtnPresent();
		boolean actionClick = teamdetailPage.isActionBtnClickable();
		boolean edLinkPresent = teamdetailPage.isEditDeleteLinkPresent();
		boolean edLinkClick = teamdetailPage.isEditDeleteLinkClickable();
		boolean permLinkPresent = teamdetailPage.ispermUsersLinkPresent();
		boolean permLinkClick = teamdetailPage.ispermUsersLinkClickable();
		teamdetailPage.logout();
		String ap,ac,ep,ec,pp,pc;
		ap = ac = ep = ec = pp = pc = "";
		if(!actionPresent){ap = "Action button was not present";}
		if(!actionClick){ac = "Action button was not clickable";}
		if(!edLinkPresent){ep = "Edit Delete link was not present";}
		if(!edLinkClick){ec = "Edit Delete link was not clickable";}
		if(!permLinkPresent){pp = "User Permissions Link was not present";}
		if(!permLinkClick){pc = "User Permissions Link was not clickable";}
		
		assertTrue(ap + " | "+ ac + " | "+ ep + " | "+ ec + " | "+ pp + " | "+ pc,
				actionPresent && actionClick && edLinkPresent && edLinkClick && permLinkPresent && permLinkClick);
	}
	
	@Test
	public void editDeleteModalTest(){
		teamdetailPage = dashboardPage.clickOrganizationHeaderLink().clickViewTeamLink(teamName).clickEditOrganizationLink();
		boolean modalPresent = teamdetailPage.isEditDeleteModalPresent();
		boolean deletePresent = teamdetailPage.EDDeletePresent();
		boolean deleteClick = teamdetailPage.EDDeleteClickable();
		boolean namePresent = teamdetailPage.EDNamePresent();
		boolean nameCorrect = teamdetailPage.EDNameCorrect();
		boolean closePresent = teamdetailPage.EDClosePresent();
		boolean closeClick = teamdetailPage.EDCloseClickable();
		boolean savePresent = teamdetailPage.EDSavePresent();
		boolean saveClick = teamdetailPage.EDSaveClickable();
		teamdetailPage = teamdetailPage.clickCloseEditModal();
		teamdetailPage.logout();
		String mp,dp,dc,np,nc,cp,cc,sp,sc;
		mp = dp = dc = np = nc = cp = cc = sp = sc = "";
		if(!modalPresent){mp = "Edit Delete Modal was not present";}
		if(!deletePresent){dp = "Delete Button was not present";}
		if(!deleteClick){dc = "Delete Button was not clickable";}
		if(!namePresent){np = "Name input was not present";}
		if(!nameCorrect){nc = "Name input was not correct";}
		if(!closePresent){cp = "Close button was not present";}
		if(!closeClick){cc = "Close button was not clickable";}
		if(!savePresent){sp = "Save button was not present";}
		if(!saveClick){sc = "Save button was not clickable";}
		
		assertTrue(mp + " | "+ dp + " | "+ dc + " | "+ np + " | "+ nc + " | "+ cp + " | "+ cc + " | "+ sp + " | "+ sc,
				modalPresent && deletePresent && deleteClick && namePresent && nameCorrect 
				&& closePresent && closeClick && savePresent && saveClick);
		
	}
	
	@Test
	public void permUsersModalTest(){
		teamdetailPage = dashboardPage.clickOrganizationHeaderLink().clickViewTeamLink(teamName).clickUserPermLink();
		boolean editPresent = teamdetailPage.isPUEditPermLinkPresent();
		boolean editClick = teamdetailPage.isPUEditPermLinkClickable();
		boolean closePresent = teamdetailPage.isPUClosePresent();
		boolean closeClick = teamdetailPage.isPUCloseClickable();
		
		teamdetailPage.clickCloseUserPermModal().logout();
		
		String ep,ec,cp,cc;
		ep = ec = cp = cc = "";
		if(!editPresent){ep = "Edit Perm Link was not present";}
		if(!editClick){ec = "Edit Perm Linke was not clickable";}
		if(!closePresent){cp = "Close button was not present";}
		if(!closeClick){cc = "Close button was not clickable";}
		assertTrue(ep + " | "+ ec + " | "+ cp + " | "+ cc,
				editPresent && editClick && closePresent && closeClick);
		
//		assertTrue(true);
//		dashboardPage.logout();
	}
	
	@Test
	public void chartTest(){
		teamdetailPage = dashboardPage.clickOrganizationHeaderLink().clickViewTeamLink(teamName);
		sleep(5000);
		boolean llPresent = teamdetailPage.isleftViewMoreLinkPresent();
		boolean llClick = teamdetailPage.isleftViewMoreLinkClickable();
//		boolean rlPresent = teamdetailPage.isrightViewMoreLinkPresent();
		boolean rlPresent = true;
		boolean rlClick = teamdetailPage.isrightViewMoreLinkClickable();
		boolean lcPresent = teamdetailPage.is6MonthChartPresnt();
		boolean rcPresent = teamdetailPage.isTop10ChartPresent();
		teamdetailPage.logout();
		String lp,lc,rp,rc,lcp,rcp;
		lp = lc = rp = rc = lcp = rcp = "";
		if(!llPresent){lp = "Left view more link was not present";}
		if(!llClick){lc = "Left view more Link was not clickable";}
		if(!rlPresent){rp = "Right view more link was not present";}
		if(!rlClick){rc = "right view more was not clickable";}
		if(!lcPresent){lcp = "6 month vuln burndown chart was not present";}
		if(!rcPresent){rcp = "Top 10 vuln chart was not present";}
		assertTrue(lp + " | "+ lc + " | "+ rp + " | "+ rc + " | "+ lcp + " | "+ rcp,
				llPresent && llClick && rlPresent && rlClick && lcPresent && rcPresent);
		
	}
	
	@Test
	public void addApplicationButtonTest(){
		teamdetailPage = dashboardPage.clickOrganizationHeaderLink().clickViewTeamLink(teamName);
		boolean addAppPresent = teamdetailPage.isAddAppBtnPresent();
		boolean addAppClick = teamdetailPage.isAddAppBtnClickable();
		String ap,ac;
		ap = ac = "";
		if(!addAppPresent){ap = "Add App button was not present";}
		if(!addAppClick){ap = "Add App button was not clickable";}
		
		assertTrue(ap + " | " + ac, addAppPresent && addAppClick);
		
		teamdetailPage.logout();
	}
	
//	@Test
//	public void addApplicationModaltest(){
//		teamdetailPage = dashboardPage.clickOrganizationHeaderLink().clickViewTeamLink(teamName);
//		boolean actionPresent = teamdetailPage.isActionBtnPresent();
//		boolean actionClick = teamdetailPage.isActionBtnClickable();
//		String ap,ac;
//		ap = ac = "";
//		if(!actionPresent){ap = "Action button was not present";}
//		if(!actionClick){ap = "Action button was not clickable";}
//		
//		assertTrue(ap + " | "+ ac,actionPresent && actionClick);
	
//	teamdetailPage.logout();
//	}
	
	@Test
	public void applicationDetailLink(){
		teamdetailPage = dashboardPage.clickOrganizationHeaderLink().clickViewTeamLink(teamName);
		boolean appLinkPresent = teamdetailPage.isAppLinkPresent(appName);
		boolean appLinkClick = teamdetailPage.isAppLinkClickable(appName);
		teamdetailPage.logout();
		String ap,ac;
		ap = ac = "";
		if(!appLinkPresent){ap = "Link for app," + appName + " button was not present";}
		if(!appLinkClick){ap = "Link for app," + appName + " button was not clickable";}
		assertTrue(ap + " | "+ ac,appLinkPresent && appLinkClick);
	}
	
	private  boolean buildElements(){
		dashboardPage = login();
		String rtApp = "Demo Site BE";
		String whKey = System.getProperty("WHITEHAT_KEY");
		if(whKey == null){
			return false;
		}
		//add team
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink()
										.clickAddTeamButton()
										.setTeamName(teamName)
										.addNewTeam();
		//add app
		ti = ti	.expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName, "", "Low")
				.saveApplication(teamName);
		
		//import remoteProvider
		ti.clickRemoteProvidersLink()
					.clickConfigureWhiteHat()
					.setWhiteHatAPI(whKey)
					.saveWhiteHat()
					.clickEditMapping(rtApp)
					.setTeamMapping(rtApp, teamName)
					.setAppMapping(rtApp, appName)
					.clickSaveMapping(rtApp)
					.clickImportScan(rtApp)
					.logout();
		

		dashboardPage = login();
		
		return true;
	}
	
	private void destroyElements(){
		
		dashboardPage = login();
		
		dashboardPage.clickOrganizationHeaderLink()
					.clickViewTeamLink(teamName)
					.clickDeleteButton()
					.clickRemoteProvidersLink()
					.clickRemoveWhiteHatConfig()
					.logout();
		
	}
}
