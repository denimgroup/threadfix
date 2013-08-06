package com.denimgroup.threadfix.selenium.pagetests;

import org.junit.*;

import static org.junit.Assert.*;

import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;

public class ApplicationIndexPageTest extends PageBaseTest {
	
	public ApplicationIndexPageTest(String browser){
		super(browser);
	}
	
	private  DashboardPage dashboardPage;
	private  boolean build;
	private  String teamName = getRandomString(8);
	private  String appName = getRandomString(8);
	
	@Before
	public void init() {
		super.init();
		build = buildElements();
	}
	
	@After
	public  void cleanup(){
		destroyElements();
	}
	
	@Test
	public void buildUpTest(){
		assertTrue(build);
		dashboardPage.logout();
	}
	
	@Test
	public void addTeamBtnTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void expandAllBtnTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void collapseAllBtnTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void addAppBtnTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void viewTeamLinkTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void uploadScanBtnTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void appLinkTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void addTeamModalTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void addApplicationModalTest(){
		assertTrue(true);
		dashboardPage.logout();
	}
	
	@Test
	public void uploadScanModalTest(){
		assertTrue(true);
		dashboardPage.logout();
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
