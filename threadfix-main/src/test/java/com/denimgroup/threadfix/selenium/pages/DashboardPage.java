package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class DashboardPage extends BasePage{

	public DashboardPage(WebDriver webdriver) {
		super(webdriver);

	}
	
	public boolean is6MonthGraphPresent(){
		return driver.findElementById("leftTileReport").isDisplayed();
	}
	
	public boolean isTop10GraphPresent(){
		return driver.findElementById("rightTileReport").isDisplayed();
	}
	
	public ReportsIndexPage click6MonthViewMore(){
		driver.findElementById("leftViewMore").click();
		return new ReportsIndexPage(driver);
	}
	
	public ReportsIndexPage clickTop10ViewMore(){
		driver.findElementById("rightViewMore").click();
		return new ReportsIndexPage(driver);
	}
	
	public ApplicationDetailPage clickLatestUploadApp(){
		driver.findElementById("scanApplicationLink1").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
		
	public ScanDetailPage clickLatestUploadScan(){
		driver.findElementById("scanLink1").click();
		return new ScanDetailPage(driver);
	}
	
	public ApplicationDetailPage clickLatestCommentApp(){
		driver.findElementById("commentUser1").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public VulnerabilityDetailPage clickLatestCommentLink(){
		driver.findElementsByLinkText("View").get(0).click();
		return new VulnerabilityDetailPage(driver);
	}
	
	public int getNumUploads(){
		return driver.findElementById("wafTableBody").findElements(By.className("bodyRow")).size();
	}
	
	public int getNumComments(){
		return driver.findElementsByClassName("bodyRow").size()-getNumUploads();
	}
}
