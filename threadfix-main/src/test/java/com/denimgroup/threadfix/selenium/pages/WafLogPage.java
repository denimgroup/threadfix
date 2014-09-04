package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;

/**
 * Created by mghanizadeh on 9/3/2014.
 */
public class WafLogPage extends BasePage{

    public WafLogPage(WebDriver webdriver) {
        super(webdriver);
    }

    public WafIndexPage clickContinue() {
        driver.findElementByLinkText("Continue").click();
        return new WafIndexPage(driver);
    }
}
