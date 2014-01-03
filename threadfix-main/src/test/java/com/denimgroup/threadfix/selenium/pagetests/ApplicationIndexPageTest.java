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
		super.shutDown();
	}
	
//	@Test
//	public void buildUpTest(){
//		assertTrue(build);
//		dashboardPage.logout();
//	}

	@Test
	public void addTeamBtnTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		boolean click = ti.isAddTeamBtnClickable();
		boolean present = ti.isAddTeamBtnPresent();
		String c = "";
		String p = "";
		if(!click){
			c = "Add Team button is not clickable";
		}
		
		if(!present){
			p = "Add Team button is not present";
		}
		assertTrue(p + " | "+ c,click && present);
		ti.logout();
	}


	@Test
	public void expandAllBtnTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		boolean click = ti.isExpandAllBtnClickable();
		boolean present = ti.isExpandAllBtnPresent();
		String c = "";
		String p = "";
		if(!click){
			c = "Expand All button is not clickable";
		}
		
		if(!present){
			p = "Expand All button is not present";
		}
		assertTrue(p + " | "+ c,click && present);
		ti.logout();
	}
	
	@Test
	public void collapseAllBtnTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		boolean click = ti.isCollapseAllBtnClickable();
		boolean present = ti.isCollapseAllBtnPresent();
		String c = "";
		String p = "";
		if(!click){
			c = "Collapse All button is not clickable";
		}
		
		if(!present){
			p = "Collapse All button is not present";
		}
		assertTrue(p + " | "+ c,click && present);
		ti.logout();
	}
	
	@Test
	public void addAppBtnTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		boolean click = ti.isAddAppBtnClickable(teamName);
		boolean present = ti.isAddAppBtnPresent(teamName);
		String c = "";
		String p = "";
		if(!click){
			c = "Add App button is not clickable";
		}
		
		if(!present){
			p = "Add App button is not present";
		}
		assertTrue(p + " | "+ c,click && present);
		ti.logout();
	}


	@Test
	public void viewTeamLinkTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		boolean click = ti.isViewTeamLinkClickable(teamName);
		boolean present = ti.isViewTeamLinkPresent(teamName);
		String c = "";
		String p = "";
		if(!click){
			c = "View Team Link button is not clickable";
		}
		
		if(!present){
			p = "View Team Link button is not present";
		}
		assertTrue(p + " | "+ c,click && present);
		ti.logout();
	}


	@Test
	public void uploadScanBtnTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink().expandTeamRowByIndex(teamName);
		boolean click = ti.isUploadScanClickable(teamName, appName);
//		boolean present = ti.isUploadScanPresent(teamName, appName);
		boolean present = click;
		String c = "";
		String p = "";
		if(!click){
			c = "Upload Scan button is not clickable";
		}
		
		if(!present){
			p = "Upload Scan button is not present";
		}
		assertTrue(p + " | "+ c,click && present);
		ti.logout();
	}


	@Test
	public void appLinkTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink().expandTeamRowByIndex(teamName);
		boolean click = ti.isAppLinkClickable(appName);
		boolean present = ti.isAppLinkPresent(appName);
		String c = "";
		String p = "";
		if(!click){
			c = "App Link button is not clickable";
		}
		
		if(!present){
			p = "App Link button is not present";
		}
		assertTrue(p + " | "+ c,click && present);
		ti.logout();
	}


	@Test
	public void addTeamModalTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink().clickAddTeamButton();
		boolean modalPresent = ti.isAddTeamModalPresent();
		boolean namePresent = ti.isATNameFieldPresent();
		boolean nameFunc = ti.isATNameFieldFunctional();
		boolean closePresent = ti.isCloseATButtonPresent();
		boolean closeClick = ti.isCloseATButtonClickable();
		boolean addPresent = ti.isAddTeamATButtonPresent();
		boolean addClick = ti.isAddTeamATButtonClickable();
		String mp,np,nf,cp,cc,ap,ac;
		mp = np = nf = cp = cc = ap = ac = "";
		if(!modalPresent){
			mp = "Add Team modal is not present";
		}
		
		if(!namePresent){
			np = "Add Team Name input is not present";
		}
		
		if(!nameFunc){
			nf = "Add Team Name input is not functional";
		}
		if(!closePresent){
			cp = "Add Team close modal button is not present";
		}
		if(!closeClick){
			cc = "Add Team close modal button is not present";
		}
		if(!addPresent){
			ap = "Add Team save button is not present";
		}
		if(!addClick){
			ac = "Add Team save button is not present";
		}
		
		assertTrue(mp + " | "+ np + " | "+ nf + " | "+ cp + " | "+ cc + " | "+ ap + " | "+ ac,
				modalPresent && namePresent && nameFunc && closePresent && closeClick && addPresent && addClick);
		ti.clickCloseAddTeamModal().logout();
	}


	@Test
	public void addApplicationModalTest(){
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink().clickAddNewApplication(teamName);
		boolean modalPresent = ti.isAddAppModalPresent(teamName);
		boolean namePresent = ti.isAPNameFieldPresent(teamName);
		boolean nameFunc = ti.isAPNameFieldFunctional(teamName);
//		boolean nameFunc = true;
		boolean urlPresent = ti.isURLFieldPresent(teamName);
		boolean urlFunc = ti.isURlFieldFunctional(teamName);
		boolean idPresent = ti.isAPIDFieldPresent(teamName);
		boolean idFunc = ti.isAPIDFieldFunctional(teamName);
		boolean critcPresent = ti.isAPCriticalityPresent(teamName);
		boolean critcFunc = ti.isAPCriticalityCorrect(teamName);
		boolean closePresent = ti.isCloseAPButtonPresent(teamName);
		boolean closeClick = ti.isCloseAPButtonClickable(teamName);
		boolean addPresent = ti.isAddTeamAPButtonPresent(teamName);
		boolean addClick = ti.isAddTeamAPButtonClickable(teamName);
		String mp,np,nf,up,uf,ip,iff,cp,cf,clp,clc,ap,ac;
		mp=np=nf=up=uf=ip=iff=cp=cf=clp=clc=ap=ac = "";
		if(!modalPresent){
			mp = "Add App modal is not present";
		}
		
		if(!namePresent){
			np = "Add app name input is not present";
		}
		if(!nameFunc){
			nf = "Add app name input is not functional";
		}
		if(!urlPresent){
			up = "Add app url input is not present";
		}
		if(!urlFunc){
			uf = "Add app url input is not functional";
		}
		if(!idPresent){
			ip = "Add app id input is not present";
		}
		if(!idFunc){
			iff = "Add app id input is not functional";
		}
		if(!critcPresent){
			cp = "Add app critc select is not present";
		}
		if(!critcFunc){
			cf = "Add app critc select is not correct";
		}
		if(!closePresent){
			clp = "Add app close button is not present";
		}
		if(!closeClick){
			clc = "Add app close button is not clickable";
		}
		if(!addPresent){
			ap = "Add app add button is not present";
		}
		if(!addClick){
			ac = "Add app add button is not clickable";
		}
		assertTrue(mp + " | "+ np + " | "+ nf + " | "+ up + " | "+ uf + " | "+ ip + " | "+ iff 
				+ " | "+ cp + " | "+ cf + " | "+ clp + " | "+ clc + " | "+ ap + " | "+ ac,
				modalPresent && namePresent && nameFunc && urlPresent && urlFunc && idPresent && idFunc 
				&& critcPresent && critcFunc && closePresent && closeClick && addPresent && addClick);
		ti.clickCloseAddAppModal(teamName).logout();
	}
	
//	TODO (different on each browser)
//	@Test
//	public void uploadScanModalTest(){
//		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
//		boolean click = ti.isAddTeamBtnClickable();
//		boolean present = ti.isAddTeamBtnPresent();
//		String c = "";
//		String p = "";
//		if(!click){
//			c = "Add Team button is not clickable";
//		}
//		
//		if(!present){
//			p = "Add Team button is not present";
//		}
//		assertTrue(p + " | "+ c,click && present);
//		assertTrue(true);
//		dashboardPage.logout();
//	}
	
	
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
		ti = ti	.expandTeamRowByIndex(teamName)
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
