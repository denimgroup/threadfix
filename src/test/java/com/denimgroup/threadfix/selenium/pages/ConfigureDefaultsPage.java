package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

public class ConfigureDefaultsPage extends BasePage {
	


	public ConfigureDefaultsPage(WebDriver webdriver) {
		super(webdriver);
	}
	
	public ConfigureDefaultsPage setRoleSelect(String code){
		new Select(driver.findElementById("roleSelect")).selectByVisibleText(code);
		return this;
	}

	public ConfigureDefaultsPage checkGlobalGroupCheckbox() {
		driver.findElementById("globalGroupEnabledCheckbox").click();
		return this;
	}
	
	public ConfigureDefaultsPage clickUpdateDefaults() {
		driver.findElementById("updateDefaultsButton").click();
		return new ConfigureDefaultsPage(driver);
	}
	
	public boolean isSaveSuccessful(){
		return driver.findElementByClassName("alert-success").getText().trim().contains("Configuration was saved successfully.");
	}
}
