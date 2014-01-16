package com.denimgroup.threadfix.framework;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import com.denimgroup.threadfix.framework.enums.FrameworkType;

public class FrameworkCalculatorTests {
	
	@Test
	public void bodgeitTest() {
		FrameworkType type = FrameworkCalculator.getType(new File(TestConstants.BODGEIT_SOURCE_LOCATION));
		assertTrue("Didn't find JSP.", type == FrameworkType.JSP);
	}
	
	@Test
	public void wavsepTest() {
		FrameworkType type = FrameworkCalculator.getType(new File(TestConstants.WAVSEP_SOURCE_LOCATION));
		assertTrue("Didn't find JSP.", type == FrameworkType.JSP);
	}
}
