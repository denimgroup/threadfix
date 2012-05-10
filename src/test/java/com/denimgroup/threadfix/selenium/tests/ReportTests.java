package com.denimgroup.threadfix.selenium.tests;

import java.util.Random;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.selenium.pages.AddChannelPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.OrganizationDetailPage;
import com.denimgroup.threadfix.selenium.pages.OrganizationIndexPage;
import com.denimgroup.threadfix.selenium.pages.UploadScanPage;

public class ReportTests extends BaseTest {

	private WebDriver driver;
	private static LoginPage loginPage;
	public ApplicationDetailPage applicationDetailPage;
	public UploadScanPage uploadScanPage;
	public AddChannelPage addChannelPage;
	public OrganizationIndexPage organizationIndexPage;
	public OrganizationDetailPage organizationDetailPage;
	
	Random generator = new Random();
	
	private String[] criticalities = { ApplicationCriticality.LOW,
			ApplicationCriticality.MEDIUM,
			ApplicationCriticality.HIGH,
			ApplicationCriticality.CRITICAL };
	
	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	/**
	 * This is a smoke test, to be run on a blank database.
	 * It adds a bunch of apps with random criticalities and scan uploads and then tells 
	 * you what the basic statistics should be.
	 * 
	 * Requires human checking.
	 * 
	 * TODO write tests that aren't smoke tests
	 */
	@Ignore
	@Test
	public void portfolioTest() {
		organizationIndexPage = loginPage.login("user", "password");
		
		int numOrgs = 5;
		int numAppsPerOrg = 5;
		String[] orgs = new String[numOrgs];
		
		Integer[] appsByCriticality = new Integer[] { 0, 0, 0, 0 };
		Integer[] appsNeverScannedByCriticality = new Integer[] {0, 0, 0, 0};
		
		for (int i = 0; i < numOrgs; i++) {
			orgs[i] = getRandomString(20);
			organizationDetailPage = organizationIndexPage.clickAddOrganizationButton()
														  .setNameInput(orgs[i])
														  .clickSubmitButtonValid();
			
			for (int j = 0; j < numAppsPerOrg; j++) {
				int index = generator.nextInt(4);
				appsByCriticality[index] += 1;
				applicationDetailPage = organizationDetailPage.clickAddApplicationLink()
															  .setNameInput(getRandomString(i + 5))
															  .setUrlInput("http://dummyurl.com")
															  .setCriticalitySelect(criticalities[index])
															  .clickAddApplicationButton();
				
				boolean hasScan = generator.nextBoolean();
				if (hasScan) {
					applicationDetailPage.clickUploadScanLinkFirstTime()
										 .setChannelTypeSelect(ChannelType.ARACHNI)
										 .clickAddChannelButton()
										 .setFileInput(ScanTests.getScanFilePath("Dynamic","Arachni","php-demo.xml"))
										 .setChannelSelect(ChannelType.ARACHNI)
										 .clickUploadScanButton();
				} else {
					appsNeverScannedByCriticality[index] += 1;
				}
				
				organizationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
					   										  .clickOrganizationLink(orgs[i]);
				
			}
			
			organizationIndexPage = organizationDetailPage.clickOrganizationHeaderLink();
		}
		
		System.out.println("Critical: " + (100.0 * appsNeverScannedByCriticality[3] / appsByCriticality[3]) );
		System.out.println("High: " + (100.0 * appsNeverScannedByCriticality[2] / appsByCriticality[2]) );
		System.out.println("Medium: " + (100.0 * appsNeverScannedByCriticality[1] / appsByCriticality[1]) );
		System.out.println("Low: " + (100.0 * appsNeverScannedByCriticality[0] / appsByCriticality[0]) );
	}
	
}
