package com.denimgroup.threadfix.selenium.pages;

import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class UserPermissionsPage extends BasePage {

	public UserPermissionsPage(WebDriver webdriver) {
		super(webdriver);
	}
	
	public UserPermissionsPage clickAddPermissionsLink(){
		driver.findElementById("addPermissionButton").click();
		waitForElement(driver.findElementById("newAccessControlMapForm"));
		return new UserPermissionsPage(driver);
	}
	
	
	public int getIndex(String teamName, String Application, String role){
		//waiting on ids for the fields
		List<WebElement> teams;
		List<WebElement> apps;
		List<WebElement> roles;
		
	}

}
