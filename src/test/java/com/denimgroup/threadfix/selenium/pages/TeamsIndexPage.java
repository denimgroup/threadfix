package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class TeamsIndexPage extends BasePage{
	private WebElement addTeamModalButton;

	public TeamsIndexPage(WebDriver webdriver) {
		super(webdriver);
		
		addTeamModalButton = driver.findElementById("addTeamModalButton");
	}
	
	public TeamsIndexPage clickAddTeamButton() {
		addTeamModalButton.click();
		return new TeamsIndexPage(driver);	
	}
}
