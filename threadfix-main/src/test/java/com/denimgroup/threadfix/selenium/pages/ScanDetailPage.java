package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;

public class ScanDetailPage extends BasePage{

	public ScanDetailPage(WebDriver webdriver) {
		super(webdriver);

	}
	
	public String getScanHeader(){
		return getH2Tag().trim();
	}
}
