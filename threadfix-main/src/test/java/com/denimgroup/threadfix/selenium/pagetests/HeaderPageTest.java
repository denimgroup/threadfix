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
package com.denimgroup.threadfix.selenium.pagetests;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.apache.poi.hssf.record.common.FeatFormulaErr2;
import org.junit.*;

import com.denimgroup.threadfix.selenium.pages.ApiKeysIndexPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.ConfigureDefaultsPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.ErrorLogPage;
import com.denimgroup.threadfix.selenium.pages.FindingEditPage;
import com.denimgroup.threadfix.selenium.pages.MergeFindingPage;
import com.denimgroup.threadfix.selenium.pages.RemoteProvidersIndexPage;
import com.denimgroup.threadfix.selenium.pages.ReportsIndexPage;
import com.denimgroup.threadfix.selenium.pages.RolesIndexPage;
import com.denimgroup.threadfix.selenium.pages.ScanDetailPage;
import com.denimgroup.threadfix.selenium.pages.ScanIndexPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserChangePasswordPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserPermissionsPage;
import com.denimgroup.threadfix.selenium.pages.VulnerabilityDetailPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;
import com.denimgroup.threadfix.selenium.pages.WafRulesPage;

public class HeaderPageTest extends PageBaseTest {
	public HeaderPageTest(String browser) {
		super(browser);
	}

//	private static LoginPage loginPage;
//	private RemoteWebDriver driver;
	private  DashboardPage dashboardPage;
	private  boolean build;
	private  String teamName = getRandomString(8);;
	private  String wafName = getRandomString(8);;
	private  String appName = getRandomString(8);;
	
//	@BeforeClass
//	public void setup(){
//		build = buildElements();
//	}
	
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
	public void dashboardHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		int i = 0;
		Map<String, Boolean> present = PAGE_MAP;
		Map<String, Boolean> clickable = PAGE_MAP;
		//Dashboard
		present.put(PAGE_LIST[i], dashboardPage.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], dashboardPage.isDashboardMenuLinkClickable());
		
		//Applications Index
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		present.put(PAGE_LIST[i], ti.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], ti.isDashboardMenuLinkClickable());
		
		//Team Detail
		TeamDetailPage td = ti.clickViewTeamLink(teamName);
		present.put(PAGE_LIST[i], td.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], td.isDashboardMenuLinkClickable());
		
		//Application Detail
		ApplicationDetailPage ad = td.clickOrganizationHeaderLink()
									.expandTeamRowByName(teamName)
									.clickViewAppLink(appName, teamName);
		present.put(PAGE_LIST[i], ad.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], ad.isDashboardMenuLinkClickable());
		
		//Scan Index
		ScanIndexPage si = ad.clickScansHeaderLink();
		present.put(PAGE_LIST[i], si.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], si.isDashboardMenuLinkClickable());
		
		//Scan Detail
		ScanDetailPage sd = si.clickAnyViewScanLink();
		present.put(PAGE_LIST[i], sd.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], sd.isDashboardMenuLinkClickable());
		
		//Finding Detail
		FindingEditPage fe = sd.clickViewFinding(1);
		present.put(PAGE_LIST[i], fe.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], fe.isDashboardMenuLinkClickable());
		
		//Vuln Detail
		VulnerabilityDetailPage vd = fe.clickViewVuln();
		present.put(PAGE_LIST[i], vd.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], vd.isDashboardMenuLinkClickable());
		
		//Merge Finding Page
		MergeFindingPage mf = vd.clickViewFinding().clickMergeFinding();
		present.put(PAGE_LIST[i], mf.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], mf.isDashboardMenuLinkClickable());
		
		//Reports Index
		ReportsIndexPage ri = mf.clickReportsHeaderLink();
		present.put(PAGE_LIST[i], ri.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], ri.isDashboardMenuLinkClickable());
		
		//Change Password
		UserChangePasswordPage pc = ri.clickChangePasswordLink();
		present.put(PAGE_LIST[i], pc.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], pc.isDashboardMenuLinkClickable());
		
		//Api key index
		ApiKeysIndexPage ai = pc.clickApiKeysLink();
		present.put(PAGE_LIST[i], ai.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], ai.isDashboardMenuLinkClickable());
		
		//waf index
		WafIndexPage wi = ai.clickWafsHeaderLink();
		present.put(PAGE_LIST[i], wi.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], wi.isDashboardMenuLinkClickable());
		
		//waf rules
		WafRulesPage wr = wi.clickRules(wafName);
		present.put(PAGE_LIST[i], wr.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], wr.isDashboardMenuLinkClickable());
		
		//defect Trackers
		DefectTrackerIndexPage di = wr.clickDefectTrackersLink();
		present.put(PAGE_LIST[i], di.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], di.isDashboardMenuLinkClickable());
		
		//remote providers
		RemoteProvidersIndexPage rem = di.clickRemoteProvidersLink();
		present.put(PAGE_LIST[i], rem.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], rem.isDashboardMenuLinkClickable());
		
		//user index
		UserIndexPage ui = rem.clickManageUsersLink();
		present.put(PAGE_LIST[i], ui.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], ui.isDashboardMenuLinkClickable());
		
		//user permissions
		UserPermissionsPage up = ui.clickEditPermissions("user");
		present.put(PAGE_LIST[i], up.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], up.isDashboardMenuLinkClickable());
		
		//roles index
		RolesIndexPage role = up.clickManageRolesLink();
		present.put(PAGE_LIST[i], role.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], role.isDashboardMenuLinkClickable());
		
		//logs
		ErrorLogPage ep = role.clickViewLogsLink();
		present.put(PAGE_LIST[i], ep.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], ep.isDashboardMenuLinkClickable());
		
		//configure defaults
		ConfigureDefaultsPage cd = ep.clickConfigureDefaultsLink();
		present.put(PAGE_LIST[i], cd.isDashboardMenuLinkPresent());
		clickable.put(PAGE_LIST[i++], cd.isDashboardMenuLinkClickable());
		
		dashboardPage.logout();
		
		String alert = mapCheck(present, "DashBoard menu link is not present on ")
						.concat(mapCheck(clickable,"DashBoard menu link is not clickable on "));
		
		assertTrue(alert,alert.equals(""));
	}
	
	@Test
	public void applicationsHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		int i = 0;
		Map<String, Boolean> present = PAGE_MAP;
		Map<String, Boolean> clickable = PAGE_MAP;
		//Dashboard
		clickable.put(PAGE_LIST[i], dashboardPage.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], dashboardPage.isApplicationMenuLinkPresent());
		
		//Applications Index
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		clickable.put(PAGE_LIST[i], ti.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], ti.isApplicationMenuLinkPresent());
		
		//Team Detail
		TeamDetailPage td = ti.clickViewTeamLink(teamName);
		clickable.put(PAGE_LIST[i], td.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], td.isApplicationMenuLinkPresent());
		
		//Application Detail
		ApplicationDetailPage ad = td.clickOrganizationHeaderLink()
									.expandTeamRowByName(teamName)
									.clickViewAppLink(appName, teamName);
		clickable.put(PAGE_LIST[i], ad.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], ad.isApplicationMenuLinkPresent());
		
		//Scan Index
		ScanIndexPage si = ad.clickScansHeaderLink();
		clickable.put(PAGE_LIST[i], si.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], si.isApplicationMenuLinkPresent());
		
		//Scan Detail
		ScanDetailPage sd = si.clickAnyViewScanLink();
		clickable.put(PAGE_LIST[i], sd.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], sd.isApplicationMenuLinkPresent());
		
		//Finding Detail
		FindingEditPage fe = sd.clickViewFinding(1);
		clickable.put(PAGE_LIST[i], fe.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], fe.isApplicationMenuLinkPresent());
		
		//Vuln Detail
		VulnerabilityDetailPage vd = fe.clickViewVuln();
		clickable.put(PAGE_LIST[i], vd.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], vd.isApplicationMenuLinkPresent());
		
		//Merge Finding Page
		MergeFindingPage mf = vd.clickViewFinding().clickMergeFinding();
		clickable.put(PAGE_LIST[i], mf.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], mf.isApplicationMenuLinkPresent());
		
		//Reports Index
		ReportsIndexPage ri = mf.clickReportsHeaderLink();
		clickable.put(PAGE_LIST[i], ri.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], ri.isApplicationMenuLinkPresent());
		
		//Change Password
		UserChangePasswordPage pc = ri.clickChangePasswordLink();
		clickable.put(PAGE_LIST[i], pc.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], pc.isApplicationMenuLinkPresent());
		
		//Api key index
		ApiKeysIndexPage ai = pc.clickApiKeysLink();
		clickable.put(PAGE_LIST[i], ai.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], ai.isApplicationMenuLinkPresent());
		
		//waf index
		WafIndexPage wi = ai.clickWafsHeaderLink();
		clickable.put(PAGE_LIST[i], wi.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], wi.isApplicationMenuLinkPresent());
		
		//waf rules
		WafRulesPage wr = wi.clickRules(wafName);
		clickable.put(PAGE_LIST[i], wr.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], wr.isApplicationMenuLinkPresent());
		
		//defect Trackers
		DefectTrackerIndexPage di = wr.clickDefectTrackersLink();
		clickable.put(PAGE_LIST[i], di.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], di.isApplicationMenuLinkPresent());
		
		//remote providers
		RemoteProvidersIndexPage rem = di.clickRemoteProvidersLink();
		clickable.put(PAGE_LIST[i], rem.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], rem.isApplicationMenuLinkPresent());
		
		//user index
		UserIndexPage ui = rem.clickManageUsersLink();
		clickable.put(PAGE_LIST[i], ui.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], ui.isApplicationMenuLinkPresent());
		
		//user permissions
		UserPermissionsPage up = ui.clickEditPermissions("user");
		clickable.put(PAGE_LIST[i], up.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], up.isApplicationMenuLinkPresent());
		
		//roles index
		RolesIndexPage role = up.clickManageRolesLink();
		clickable.put(PAGE_LIST[i], role.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], role.isApplicationMenuLinkPresent());
		
		//logs
		ErrorLogPage ep = role.clickViewLogsLink();
		clickable.put(PAGE_LIST[i], ep.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], ep.isApplicationMenuLinkPresent());
		
		//configure defaults
		ConfigureDefaultsPage cd = ep.clickConfigureDefaultsLink();
		clickable.put(PAGE_LIST[i], cd.isApplicationMenuLinkClickable());
		present.put(PAGE_LIST[i++], cd.isApplicationMenuLinkPresent());
		
		dashboardPage.logout();
		
		String alert = mapCheck(present, "Application menu link is not present on ")
				.concat(mapCheck(clickable,"Application menu link is not clickable on "));

		assertTrue(alert,alert.equals(""));

//		assertTrue(mapCheck(present) + "did not have the Application Menu link element",mapCheck(present).equals(""));
	}
	
	@Test
	public void scansHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		int i = 0;
		Map<String, Boolean> present = PAGE_MAP;
		Map<String, Boolean> clickable = PAGE_MAP;
		//Dashboard
		clickable.put(PAGE_LIST[i], dashboardPage.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], dashboardPage.isScansMenuLinkPresent());
		
		//Applications Index
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		clickable.put(PAGE_LIST[i], ti.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], ti.isScansMenuLinkPresent());
		
		//Team Detail
		TeamDetailPage td = ti.clickViewTeamLink(teamName);
		clickable.put(PAGE_LIST[i], td.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], td.isScansMenuLinkPresent());
		
		//Application Detail
		ApplicationDetailPage ad = td.clickOrganizationHeaderLink()
									.expandTeamRowByName(teamName)
									.clickViewAppLink(appName, teamName);
		clickable.put(PAGE_LIST[i], ad.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], ad.isScansMenuLinkPresent());
		
		//Scan Index
		ScanIndexPage si = ad.clickScansHeaderLink();
		clickable.put(PAGE_LIST[i], si.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], si.isScansMenuLinkPresent());
		
		//Scan Detail
		ScanDetailPage sd = si.clickAnyViewScanLink();
		clickable.put(PAGE_LIST[i], sd.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], sd.isScansMenuLinkPresent());
		
		//Finding Detail
		FindingEditPage fe = sd.clickViewFinding(1);
		clickable.put(PAGE_LIST[i], fe.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], fe.isScansMenuLinkPresent());
		
		//Vuln Detail
		VulnerabilityDetailPage vd = fe.clickViewVuln();
		clickable.put(PAGE_LIST[i], vd.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], vd.isScansMenuLinkPresent());
		
		//Merge Finding Page
		MergeFindingPage mf = vd.clickViewFinding().clickMergeFinding();
		clickable.put(PAGE_LIST[i], mf.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], mf.isScansMenuLinkPresent());
		
		//Reports Index
		ReportsIndexPage ri = mf.clickReportsHeaderLink();
		clickable.put(PAGE_LIST[i], ri.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], ri.isScansMenuLinkPresent());
		
		//Change Password
		UserChangePasswordPage pc = ri.clickChangePasswordLink();
		clickable.put(PAGE_LIST[i], pc.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], pc.isScansMenuLinkPresent());
		
		//Api key index
		ApiKeysIndexPage ai = pc.clickApiKeysLink();
		clickable.put(PAGE_LIST[i], ai.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], ai.isScansMenuLinkPresent());
		
		//waf index
		WafIndexPage wi = ai.clickWafsHeaderLink();
		clickable.put(PAGE_LIST[i], wi.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], wi.isScansMenuLinkPresent());
		
		//waf rules
		WafRulesPage wr = wi.clickRules(wafName);
		clickable.put(PAGE_LIST[i], wr.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], wr.isScansMenuLinkPresent());
		
		//defect Trackers
		DefectTrackerIndexPage di = wr.clickDefectTrackersLink();
		clickable.put(PAGE_LIST[i], di.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], di.isScansMenuLinkPresent());
		
		//remote providers
		RemoteProvidersIndexPage rem = di.clickRemoteProvidersLink();
		clickable.put(PAGE_LIST[i], rem.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], rem.isScansMenuLinkPresent());
		
		//user index
		UserIndexPage ui = rem.clickManageUsersLink();
		clickable.put(PAGE_LIST[i], ui.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], ui.isScansMenuLinkPresent());
		
		//user permissions
		UserPermissionsPage up = ui.clickEditPermissions("user");
		clickable.put(PAGE_LIST[i], up.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], up.isScansMenuLinkPresent());
		
		//roles index
		RolesIndexPage role = up.clickManageRolesLink();
		clickable.put(PAGE_LIST[i], role.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], role.isScansMenuLinkPresent());
		
		//logs
		ErrorLogPage ep = role.clickViewLogsLink();
		clickable.put(PAGE_LIST[i], ep.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], ep.isScansMenuLinkPresent());
		
		//configure defaults
		ConfigureDefaultsPage cd = ep.clickConfigureDefaultsLink();
		clickable.put(PAGE_LIST[i], cd.isScansMenuLinkClickable());
		present.put(PAGE_LIST[i++], cd.isScansMenuLinkPresent());
		
		dashboardPage.logout();
		
		String alert = mapCheck(present, "Scans menu link is not present on ")
		.concat(mapCheck(clickable,"Scan menu link is not clickable on "));

		assertTrue(alert,alert.equals(""));
	}
	
	@Test
	public void reportsHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		int i = 0;
		Map<String, Boolean> present = PAGE_MAP;
		Map<String, Boolean> clickable = PAGE_MAP;
		//Dashboard
		clickable.put(PAGE_LIST[i], dashboardPage.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], dashboardPage.isReportsMenuLinkPresent());
		
		//Applications Index
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		clickable.put(PAGE_LIST[i], ti.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], ti.isReportsMenuLinkPresent());
		
		//Team Detail
		TeamDetailPage td = ti.clickViewTeamLink(teamName);
		clickable.put(PAGE_LIST[i], td.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], td.isReportsMenuLinkPresent());
		
		//Application Detail
		ApplicationDetailPage ad = td.clickOrganizationHeaderLink()
									.expandTeamRowByName(teamName)
									.clickViewAppLink(appName, teamName);
		clickable.put(PAGE_LIST[i], ad.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], ad.isReportsMenuLinkPresent());
		
		//Scan Index
		ScanIndexPage si = ad.clickScansHeaderLink();
		clickable.put(PAGE_LIST[i], si.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], si.isReportsMenuLinkPresent());
		
		//Scan Detail
		ScanDetailPage sd = si.clickAnyViewScanLink();
		clickable.put(PAGE_LIST[i], sd.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], sd.isReportsMenuLinkPresent());
		
		//Finding Detail
		FindingEditPage fe = sd.clickViewFinding(1);
		clickable.put(PAGE_LIST[i], fe.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], fe.isReportsMenuLinkPresent());
		
		//Vuln Detail
		VulnerabilityDetailPage vd = fe.clickViewVuln();
		clickable.put(PAGE_LIST[i], vd.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], vd.isReportsMenuLinkPresent());
		
		//Merge Finding Page
		MergeFindingPage mf = vd.clickViewFinding().clickMergeFinding();
		clickable.put(PAGE_LIST[i], mf.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], mf.isReportsMenuLinkPresent());
		
		//Reports Index
		ReportsIndexPage ri = mf.clickReportsHeaderLink();
		clickable.put(PAGE_LIST[i], ri.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], ri.isReportsMenuLinkPresent());
		
		//Change Password
		UserChangePasswordPage pc = ri.clickChangePasswordLink();
		clickable.put(PAGE_LIST[i], pc.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], pc.isReportsMenuLinkPresent());
		
		//Api key index
		ApiKeysIndexPage ai = pc.clickApiKeysLink();
		clickable.put(PAGE_LIST[i], ai.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], ai.isReportsMenuLinkPresent());
		
		//waf index
		WafIndexPage wi = ai.clickWafsHeaderLink();
		clickable.put(PAGE_LIST[i], wi.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], wi.isReportsMenuLinkPresent());
		
		//waf rules
		WafRulesPage wr = wi.clickRules(wafName);
		clickable.put(PAGE_LIST[i], wr.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], wr.isReportsMenuLinkPresent());
		
		//defect Trackers
		DefectTrackerIndexPage di = wr.clickDefectTrackersLink();
		clickable.put(PAGE_LIST[i], di.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], di.isReportsMenuLinkPresent());
		
		//remote providers
		RemoteProvidersIndexPage rem = di.clickRemoteProvidersLink();
		clickable.put(PAGE_LIST[i], rem.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], rem.isReportsMenuLinkPresent());
		
		//user index
		UserIndexPage ui = rem.clickManageUsersLink();
		clickable.put(PAGE_LIST[i], ui.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], ui.isReportsMenuLinkPresent());
		
		//user permissions
		UserPermissionsPage up = ui.clickEditPermissions("user");
		clickable.put(PAGE_LIST[i], up.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], up.isReportsMenuLinkPresent());
		
		//roles index
		RolesIndexPage role = up.clickManageRolesLink();
		clickable.put(PAGE_LIST[i], role.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], role.isReportsMenuLinkPresent());
		
		//logs
		ErrorLogPage ep = role.clickViewLogsLink();
		clickable.put(PAGE_LIST[i], ep.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], ep.isReportsMenuLinkPresent());
		
		//configure defaults
		ConfigureDefaultsPage cd = ep.clickConfigureDefaultsLink();
		clickable.put(PAGE_LIST[i], cd.isReportsMenuLinkClickable());
		present.put(PAGE_LIST[i++], cd.isReportsMenuLinkPresent());
		
		dashboardPage.logout();
		
		String alert = mapCheck(present, "Reports menu link is not present on ")
		.concat(mapCheck(clickable,"Reports menu link is not clickable on "));

		assertTrue(alert,alert.equals(""));
		
	}
	
	@Test
	public void userHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		int i = 0;
		Map<String, Boolean> present = PAGE_MAP;
		Map<String, Boolean> clickable = PAGE_MAP;
		Map<String, Boolean> pwPresent = PAGE_MAP;
		Map<String, Boolean> pwClickable = PAGE_MAP;
		Map<String, Boolean> helpPresent = PAGE_MAP;
		Map<String, Boolean> helpClickable = PAGE_MAP;
		Map<String, Boolean> logoutPresent = PAGE_MAP;
		Map<String, Boolean> logoutClickable = PAGE_MAP;
		Map<String, Boolean> menuPresent = PAGE_MAP;
		//Dashboard
		clickable.put(PAGE_LIST[i], dashboardPage.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], dashboardPage.isUsersMenuLinkPresent());
		dashboardPage.clickUserTab();
		pwPresent.put(PAGE_LIST[i], dashboardPage.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], dashboardPage.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], dashboardPage.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], dashboardPage.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], dashboardPage.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], dashboardPage.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], dashboardPage.isUserDropDownPresent());
		
		//Applications Index
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		clickable.put(PAGE_LIST[i], ti.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], ti.isUsersMenuLinkPresent());
		ti.clickUserTab();
		pwPresent.put(PAGE_LIST[i], ti.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], ti.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], ti.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], ti.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], ti.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], ti.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], ti.isUserDropDownPresent());
		
		//Team Detail
		TeamDetailPage td = ti.clickViewTeamLink(teamName);
		clickable.put(PAGE_LIST[i], td.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], td.isUsersMenuLinkPresent());
		td.clickUserTab();
		pwPresent.put(PAGE_LIST[i], td.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], td.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], td.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], td.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], td.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], td.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], td.isUserDropDownPresent());
		
		//Application Detail
		ApplicationDetailPage ad = td.clickOrganizationHeaderLink()
									.expandTeamRowByName(teamName)
									.clickViewAppLink(appName, teamName);
		clickable.put(PAGE_LIST[i], ad.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], ad.isUsersMenuLinkPresent());
		ad.clickUserTab();
		pwPresent.put(PAGE_LIST[i], ad.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], ad.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], ad.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], ad.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], ad.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], ad.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], ad.isUserDropDownPresent());
		
		//Scan Index
		ScanIndexPage si = ad.clickScansHeaderLink();
		clickable.put(PAGE_LIST[i], si.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], si.isUsersMenuLinkPresent());
		si.clickUserTab();
		pwPresent.put(PAGE_LIST[i], si.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], si.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], si.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], si.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], si.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], si.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], si.isUserDropDownPresent());
		
		//Scan Detail
		ScanDetailPage sd = si.clickAnyViewScanLink();
		clickable.put(PAGE_LIST[i], sd.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], sd.isUsersMenuLinkPresent());
		sd.clickUserTab();
		pwPresent.put(PAGE_LIST[i], sd.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], sd.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], sd.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], sd.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], sd.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], sd.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], sd.isUserDropDownPresent());
		
		//Finding Detail
		FindingEditPage fe = sd.clickViewFinding(1);
		clickable.put(PAGE_LIST[i], fe.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], fe.isUsersMenuLinkPresent());
		fe.clickUserTab();
		pwPresent.put(PAGE_LIST[i], fe.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], fe.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], fe.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], fe.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], fe.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], fe.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], fe.isUserDropDownPresent());
		
		//Vuln Detail
		VulnerabilityDetailPage vd = fe.clickViewVuln();
		clickable.put(PAGE_LIST[i], vd.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], vd.isUsersMenuLinkPresent());
		vd.clickUserTab();
		pwPresent.put(PAGE_LIST[i], vd.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], vd.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], vd.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], vd.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], vd.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], vd.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], vd.isUserDropDownPresent());
		
		//Merge Finding Page
		MergeFindingPage mf = vd.clickViewFinding().clickMergeFinding();
		clickable.put(PAGE_LIST[i], mf.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], mf.isUsersMenuLinkPresent());
		mf.clickUserTab();
		pwPresent.put(PAGE_LIST[i], mf.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], mf.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], mf.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], mf.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], mf.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], mf.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], mf.isUserDropDownPresent());;
		
		//Reports Index
		ReportsIndexPage ri = mf.clickReportsHeaderLink();
		clickable.put(PAGE_LIST[i], ri.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], ri.isUsersMenuLinkPresent());
		ri.clickUserTab();
		pwPresent.put(PAGE_LIST[i], ri.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], ri.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], ri.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], ri.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], ri.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], ri.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], ri.isUserDropDownPresent());
		
		//Change Password
		ri.clickUserTab();
		UserChangePasswordPage pc = ri.clickChangePasswordLink();
		clickable.put(PAGE_LIST[i], pc.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], pc.isUsersMenuLinkPresent());
		pc.clickUserTab();
		pwPresent.put(PAGE_LIST[i], pc.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], pc.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], pc.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], pc.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], pc.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], pc.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], pc.isUserDropDownPresent());
		
		//Api key index
		ApiKeysIndexPage ai = pc.clickApiKeysLink();
		clickable.put(PAGE_LIST[i], ai.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], ai.isUsersMenuLinkPresent());
		ai.clickUserTab();
		pwPresent.put(PAGE_LIST[i], ai.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], ai.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], ai.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], ai.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], ai.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], ai.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], ai.isUserDropDownPresent());
		
		//waf index
		WafIndexPage wi = ai.clickWafsHeaderLink();
		clickable.put(PAGE_LIST[i], wi.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], wi.isUsersMenuLinkPresent());
		wi.clickUserTab();
		pwPresent.put(PAGE_LIST[i], wi.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], wi.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], wi.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], wi.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], wi.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], wi.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], wi.isUserDropDownPresent());
		
		//waf rules
		WafRulesPage wr = wi.clickRules(wafName);
		clickable.put(PAGE_LIST[i], wr.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], wr.isUsersMenuLinkPresent());
		wr.clickUserTab();
		pwPresent.put(PAGE_LIST[i], wr.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], wr.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], wr.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], wr.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], wr.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], wr.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], wr.isUserDropDownPresent());
		
		//defect Trackers
		DefectTrackerIndexPage di = wr.clickDefectTrackersLink();
		clickable.put(PAGE_LIST[i], di.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], di.isUsersMenuLinkPresent());
		di.clickUserTab();
		pwPresent.put(PAGE_LIST[i], di.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], di.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], di.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], di.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], di.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], di.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], di.isUserDropDownPresent());
		
		//remote providers
		RemoteProvidersIndexPage rem = di.clickRemoteProvidersLink();
		clickable.put(PAGE_LIST[i], rem.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], rem.isUsersMenuLinkPresent());
		rem.clickUserTab();
		pwPresent.put(PAGE_LIST[i], rem.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], rem.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], rem.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], rem.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], rem.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], rem.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], rem.isUserDropDownPresent());
		
		//user index
		UserIndexPage ui = rem.clickManageUsersLink();
		clickable.put(PAGE_LIST[i], ui.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], ui.isUsersMenuLinkPresent());
		ui.clickUserTab();
		pwPresent.put(PAGE_LIST[i], ui.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], ui.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], ui.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], ui.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], ui.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], ui.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], ui.isUserDropDownPresent());
		
		//user permissions
		UserPermissionsPage up = ui.clickEditPermissions("user");
		clickable.put(PAGE_LIST[i], up.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], up.isUsersMenuLinkPresent());
		up.clickUserTab();
		pwPresent.put(PAGE_LIST[i], up.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], up.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], up.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], up.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], up.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], up.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], up.isUserDropDownPresent());
		
		//roles index
		RolesIndexPage role = up.clickManageRolesLink();
		clickable.put(PAGE_LIST[i], role.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], role.isUsersMenuLinkPresent());
		role.clickUserTab();
		pwPresent.put(PAGE_LIST[i], role.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], role.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], role.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], role.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], role.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], role.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], role.isUserDropDownPresent());
		
		//logs
		ErrorLogPage ep = role.clickViewLogsLink();
		clickable.put(PAGE_LIST[i], ep.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], ep.isUsersMenuLinkPresent());
		ep.clickUserTab();
		pwPresent.put(PAGE_LIST[i], ep.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], ep.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], ep.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], ep.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], ep.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], ep.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], ep.isUserDropDownPresent());
		
		//configure defaults
		ConfigureDefaultsPage cd = ep.clickConfigureDefaultsLink();
		clickable.put(PAGE_LIST[i], cd.isUsersMenuLinkClickable());
		present.put(PAGE_LIST[i], cd.isUsersMenuLinkPresent());
		cd.clickUserTab();
		pwPresent.put(PAGE_LIST[i], cd.isChangePasswordLinkPresent());
		pwClickable.put(PAGE_LIST[i], cd.isChangePasswordMenuLinkClickable());
		helpPresent.put(PAGE_LIST[i], cd.isToggleHelpLinkPresent());
		helpClickable.put(PAGE_LIST[i], cd.isToggleHelpMenuLinkClickable());
		logoutPresent.put(PAGE_LIST[i], cd.isLogoutLinkPresent());
		logoutClickable.put(PAGE_LIST[i], cd.isLogoutMenuLinkClickable());
		menuPresent.put(PAGE_LIST[i++], cd.isUserDropDownPresent());
		cd.clickUserTab();
		dashboardPage.logout();
		
		String alert = mapCheck(present, "Users menu link is not present on ")
		.concat(mapCheck(clickable,"Users menu link is not clickable on "))
		.concat(mapCheck(pwPresent,"Change Password menu link is not present on "))
		.concat(mapCheck(pwClickable,"Change Password menu link is not clickable on "))
		.concat(mapCheck(helpPresent,"Toggle help menu link is not present on "))
		.concat(mapCheck(helpClickable,"Toggle Help menu link is not clickable on "))
		.concat(mapCheck(logoutPresent,"Logout menu link is not present on "))
		.concat(mapCheck(logoutClickable,"Logout menu link is not clickable on "))
		.concat(mapCheck(menuPresent,"Users menu dropdown is not present on "));

		assertTrue(alert,alert.equals(""));
		
	}
	
	@Test
	public void configHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		int i = 0;
		Map<String, Boolean> present = PAGE_MAP;
//		Map<String, Boolean> clickable = PAGE_MAP;
		//Dashboard
		present.put(PAGE_LIST[i++], dashboardPage.isConfigMenuLinkPresent());
		
		//Applications Index
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		present.put(PAGE_LIST[i++], ti.isConfigMenuLinkPresent());
		
		//Team Detail
		TeamDetailPage td = ti.clickViewTeamLink(teamName);
		present.put(PAGE_LIST[i++], td.isConfigMenuLinkPresent());
		
		//Application Detail
		ApplicationDetailPage ad = td.clickOrganizationHeaderLink()
									.expandTeamRowByName(teamName)
									.clickViewAppLink(appName, teamName);
		present.put(PAGE_LIST[i++], ad.isConfigMenuLinkPresent());
		
		//Scan Index
		ScanIndexPage si = ad.clickScansHeaderLink();
		present.put(PAGE_LIST[i++], si.isConfigMenuLinkPresent());
		
		//Scan Detail
		ScanDetailPage sd = si.clickAnyViewScanLink();
		present.put(PAGE_LIST[i++], sd.isConfigMenuLinkPresent());
		
		//Finding Detail
		FindingEditPage fe = sd.clickViewFinding(1);
		present.put(PAGE_LIST[i++], fe.isConfigMenuLinkPresent());
		
		//Vuln Detail
		VulnerabilityDetailPage vd = fe.clickViewVuln();
		present.put(PAGE_LIST[i++], vd.isConfigMenuLinkPresent());
		
		//Merge Finding Page
		MergeFindingPage mf = vd.clickViewFinding().clickMergeFinding();
		present.put(PAGE_LIST[i++], mf.isConfigMenuLinkPresent());
		
		//Reports Index
		ReportsIndexPage ri = mf.clickReportsHeaderLink();
		present.put(PAGE_LIST[i++], ri.isConfigMenuLinkPresent());
		
		//Change Password
		UserChangePasswordPage pc = ri.clickChangePasswordLink();
		present.put(PAGE_LIST[i++], pc.isConfigMenuLinkPresent());
		
		//Api key index
		ApiKeysIndexPage ai = pc.clickApiKeysLink();
		present.put(PAGE_LIST[i++], ai.isConfigMenuLinkPresent());
		
		//waf index
		WafIndexPage wi = ai.clickWafsHeaderLink();
		present.put(PAGE_LIST[i++], wi.isConfigMenuLinkPresent());
		
		//waf rules
		WafRulesPage wr = wi.clickRules(wafName);
		present.put(PAGE_LIST[i++], wr.isConfigMenuLinkPresent());
		
		//defect Trackers
		DefectTrackerIndexPage di = wr.clickDefectTrackersLink();
		present.put(PAGE_LIST[i++], di.isConfigMenuLinkPresent());
		
		//remote providers
		RemoteProvidersIndexPage rem = di.clickRemoteProvidersLink();
		present.put(PAGE_LIST[i++], rem.isConfigMenuLinkPresent());
		
		//user index
		UserIndexPage ui = rem.clickManageUsersLink();
		present.put(PAGE_LIST[i++], ui.isConfigMenuLinkPresent());
		
		//user permissions
		UserPermissionsPage up = ui.clickEditPermissions("user");
		present.put(PAGE_LIST[i++], up.isConfigMenuLinkPresent());
		
		//roles index
		RolesIndexPage role = up.clickManageRolesLink();
		present.put(PAGE_LIST[i++], role.isConfigMenuLinkPresent());
		
		//logs
		ErrorLogPage ep = role.clickViewLogsLink();
		present.put(PAGE_LIST[i++], ep.isConfigMenuLinkPresent());
		
		//configure defaults
		ConfigureDefaultsPage cd = ep.clickConfigureDefaultsLink();
		present.put(PAGE_LIST[i++], cd.isConfigMenuLinkPresent());
		
		dashboardPage.logout();
		
		String alert = mapCheck(present, "Config menu link is not present on ");
//		.concat(mapCheck(clickable,"DashBoard menu link is not clickable on "));

		assertTrue(alert,alert.equals(""));
	}
	
	@Test
	public void logoIsPresentTest(){
		org.junit.Assume.assumeTrue(build);
		int i = 0;
		Map<String, Boolean> present = PAGE_MAP;
		Map<String, Boolean> clickable = PAGE_MAP;
		//Dashboard
		clickable.put(PAGE_LIST[i], dashboardPage.isLogoPresent());
		present.put(PAGE_LIST[i++], dashboardPage.isLogoPresent());
		
		//Applications Index
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
		clickable.put(PAGE_LIST[i], ti.isLogoPresent());
		present.put(PAGE_LIST[i++], ti.isLogoPresent());
		
		//Team Detail
		TeamDetailPage td = ti.clickViewTeamLink(teamName);
		clickable.put(PAGE_LIST[i], td.isLogoPresent());
		present.put(PAGE_LIST[i++], td.isLogoPresent());
		
		//Application Detail
		ApplicationDetailPage ad = td.clickOrganizationHeaderLink()
									.expandTeamRowByName(teamName)
									.clickViewAppLink(appName, teamName);
		clickable.put(PAGE_LIST[i], ad.isLogoPresent());
		present.put(PAGE_LIST[i++], ad.isLogoPresent());
		
		//Scan Index
		ScanIndexPage si = ad.clickScansHeaderLink();
		clickable.put(PAGE_LIST[i], si.isLogoPresent());
		present.put(PAGE_LIST[i++], si.isLogoPresent());
		
		//Scan Detail
		ScanDetailPage sd = si.clickAnyViewScanLink();
		clickable.put(PAGE_LIST[i], sd.isLogoPresent());
		present.put(PAGE_LIST[i++], sd.isLogoPresent());
		
		//Finding Detail
		FindingEditPage fe = sd.clickViewFinding(1);
		clickable.put(PAGE_LIST[i], fe.isLogoPresent());
		present.put(PAGE_LIST[i++], fe.isLogoPresent());
		
		//Vuln Detail
		VulnerabilityDetailPage vd = fe.clickViewVuln();
		clickable.put(PAGE_LIST[i], vd.isLogoPresent());
		present.put(PAGE_LIST[i++], vd.isLogoPresent());
		
		//Merge Finding Page
		MergeFindingPage mf = vd.clickViewFinding().clickMergeFinding();
		clickable.put(PAGE_LIST[i], mf.isLogoPresent());
		present.put(PAGE_LIST[i++], mf.isLogoPresent());
		
		//Reports Index
		ReportsIndexPage ri = mf.clickReportsHeaderLink();
		clickable.put(PAGE_LIST[i], ri.isLogoPresent());
		present.put(PAGE_LIST[i++], ri.isLogoPresent());
		
		//Change Password
		UserChangePasswordPage pc = ri.clickChangePasswordLink();
		clickable.put(PAGE_LIST[i], pc.isLogoPresent());
		present.put(PAGE_LIST[i++], pc.isLogoPresent());
		
		//Api key index
		ApiKeysIndexPage ai = pc.clickApiKeysLink();
		clickable.put(PAGE_LIST[i], ai.isLogoPresent());
		present.put(PAGE_LIST[i++], ai.isLogoPresent());
		
		//waf index
		WafIndexPage wi = ai.clickWafsHeaderLink();
		clickable.put(PAGE_LIST[i], wi.isLogoPresent());
		present.put(PAGE_LIST[i++], wi.isLogoPresent());
		
		//waf rules
		WafRulesPage wr = wi.clickRules(wafName);
		clickable.put(PAGE_LIST[i], wr.isLogoPresent());
		present.put(PAGE_LIST[i++], wr.isLogoPresent());
		
		//defect Trackers
		DefectTrackerIndexPage di = wr.clickDefectTrackersLink();
		clickable.put(PAGE_LIST[i], di.isLogoPresent());
		present.put(PAGE_LIST[i++], di.isLogoPresent());
		
		//remote providers
		RemoteProvidersIndexPage rem = di.clickRemoteProvidersLink();
		clickable.put(PAGE_LIST[i], rem.isLogoPresent());
		present.put(PAGE_LIST[i++], rem.isLogoPresent());
		
		//user index
		UserIndexPage ui = rem.clickManageUsersLink();
		clickable.put(PAGE_LIST[i], ui.isLogoPresent());
		present.put(PAGE_LIST[i++], ui.isLogoPresent());
		
		//user permissions
		UserPermissionsPage up = ui.clickEditPermissions("user");
		clickable.put(PAGE_LIST[i], up.isLogoPresent());
		present.put(PAGE_LIST[i++], up.isLogoPresent());
		
		//roles index
		RolesIndexPage role = up.clickManageRolesLink();
		clickable.put(PAGE_LIST[i], role.isLogoPresent());
		present.put(PAGE_LIST[i++], role.isLogoPresent());
		
		//logs
		ErrorLogPage ep = role.clickViewLogsLink();
		clickable.put(PAGE_LIST[i], ep.isLogoPresent());
		present.put(PAGE_LIST[i++], ep.isDashboardMenuLinkPresent());
		
		//configure defaults
		ConfigureDefaultsPage cd = ep.clickConfigureDefaultsLink();
		clickable.put(PAGE_LIST[i], cd.isLogoPresent());
		present.put(PAGE_LIST[i++], cd.isLogoPresent());
		
		dashboardPage.logout();
		
		String alert = mapCheck(present, "Logo is not present on ")
		.concat(mapCheck(clickable,"Logo is not clickable on "));

		assertTrue(alert,alert.equals(""));
	}
	
	private  boolean buildElements(){
		dashboardPage = login();
		String rtApp = "Demo Site BE";
		String wafType = "mod_security";
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
		ApplicationDetailPage ap = ti.clickRemoteProvidersLink()
										.clickConfigureWhiteHat()
										.setWhiteHatAPI(whKey)
										.saveWhiteHat()
										.clickEditMapping(rtApp)
										.setTeamMapping(rtApp, teamName)
										.setAppMapping(rtApp, appName)
										.clickSaveMapping(rtApp)
										.clickImportScan(rtApp);
		
		//add attach waf
		ap.clickWafsHeaderLink()
				.clickAddWafLink()
				.createNewWaf(wafName, wafType)
				.clickCreateWaf()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickEditDeleteBtn()
				.clickAddWaf()
				.addWaf(wafName)
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
					.clickWafsHeaderLink()
					.clickDeleteWaf(wafName)
					.logout();
		
	}
	
	public final static Map<String, Boolean> PAGE_MAP = new HashMap<String, Boolean>();
	static {
		PAGE_MAP.put("Dashboard", false);
		PAGE_MAP.put("Applications Index", false);
		PAGE_MAP.put("Team Detail", false);
		PAGE_MAP.put("Application Detail", false);
		PAGE_MAP.put("Scans Index", false);
		PAGE_MAP.put("Scan Details", false);
		PAGE_MAP.put("Vuln Details", false);
		PAGE_MAP.put("Finding Details", false);
		PAGE_MAP.put("Merge Findings", false);
		PAGE_MAP.put("Reports", false);
		PAGE_MAP.put("User Password Change", false);
		PAGE_MAP.put("Api Keys", false);
		PAGE_MAP.put("Waf index", false);
		PAGE_MAP.put("Waf Rules", false);
		PAGE_MAP.put("Defect Tracker index", false);
		PAGE_MAP.put("Remote Providers", false);
		PAGE_MAP.put("User Index", false);
		PAGE_MAP.put("User Permissions", false);
		PAGE_MAP.put("Roles Index", false);
		PAGE_MAP.put("View Logs", false);
		PAGE_MAP.put("Configure Defaults", false);
	}
	
	public final static String[] PAGE_LIST = {
		"Dashboard",
		"Applications Index",
		"Team Detail",
		"Application Detail",
		"Scans Index",
		"Scan Details",
		"Finding Details",
		"Vuln Details",
		"Merge Findings",
		"Reports",
		"User Password Change",
		"Api Keys",
		"Waf index",
		"Waf Rules",
		"Defect Tracker index",
		"Remote Providers",
		"User Index",
		"User Permissions",
		"Roles Index",
		"View Logs",
		"Configure Defaults",
	};
	
	public String mapCheck(Map<String, Boolean> m, String check){
		String s = "";
		for(Map.Entry<String, Boolean> entry : m.entrySet())
			if(!entry.getValue()){
				s.concat(check + "" + entry.getKey()+", ");
			}
		return s;
	}
	
}
