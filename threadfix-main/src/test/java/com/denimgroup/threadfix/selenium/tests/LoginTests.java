package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.*;

import org.junit.*;
import org.openqa.selenium.WebDriver;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

@RunWith(Parameterized.class)
public class LoginTests extends BaseTest{
	
	private WebDriver driver;
	private static LoginPage loginPage;
	
	public LoginTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}
	
	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	@Test
	public void badUsernameTest(){
		//non existant user
		loginPage = loginPage.loginInvalid("WRONG!!!","password");
		assertTrue("Invalid login username error message was incorrect",loginPage.isloginError());
		//case check
		loginPage = loginPage.loginInvalid("USER","password");
		assertTrue("Invalid login username error message was incorrect",loginPage.isloginError());
		//whitespace
		loginPage = loginPage.loginInvalid("u s e r","password");
		assertTrue("Invalid login username error message was incorrect",loginPage.isloginError());
	}
	
	@Test
	public void badPasswordTest(){
		//wrong password
		loginPage = loginPage.loginInvalid("user","WRONG!!!");
		assertTrue("Invalid login password error message was incorrect",loginPage.isloginError());
		//case check
		loginPage = loginPage.loginInvalid("user","PASSWORD");
		assertTrue("Invalid login password error message was incorrect",loginPage.isloginError());
		//white space
		loginPage = loginPage.loginInvalid("user","p a s s w o r d");
		assertTrue("Invalid login password error message was incorrect",loginPage.isloginError());
		loginPage = loginPage.loginInvalid("user"," password ");
		assertTrue("Invalid login password error message was incorrect",loginPage.isloginError());
	}
	
	@Test
	public void validLoginLogout(){
		DashboardPage dashboardPage;
		String username = "user";
		dashboardPage = loginPage.login(username,"password");
		assertTrue("Correct user was not logged in",dashboardPage.isLoggedInUser(username));
		loginPage = dashboardPage.logout();
		assertTrue("User was not logged out",loginPage.isLoggedOut());
		
		
		
	}
	
	
}
