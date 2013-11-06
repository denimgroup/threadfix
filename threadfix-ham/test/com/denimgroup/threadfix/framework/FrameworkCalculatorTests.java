package com.denimgroup.threadfix.framework;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import com.denimgroup.threadfix.framework.engine.FrameworkCalculator;
import com.denimgroup.threadfix.framework.enums.FrameworkType;

public class FrameworkCalculatorTests {
	
	@Test
	public void petclinicTest() {
		assertTrue("Didn't find Spring.",
				FrameworkCalculator.getType(new File(TestConstants.PETCLINIC_SOURCE_LOCATION)) 
				== FrameworkType.SPRING_MVC);
	}
	
	@Test
	public void bodgeitTest() {
		assertTrue("Didn't find JSP.",
				FrameworkCalculator.getType(new File(TestConstants.BODGEIT_SOURCE_LOCATION)) 
				== FrameworkType.JSP);
	}
	
	@Test
	public void wavsepTest() {
		assertTrue("Didn't find JSP.",
				FrameworkCalculator.getType(new File(TestConstants.WAVSEP_SOURCE_LOCATION)) 
				== FrameworkType.JSP);
	}
}
