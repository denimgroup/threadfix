package com.denimgroup.threadfix.service.framework;

public class TestConstants {
	private TestConstants(){}
	
	private static final String testRoot = "C:\\test\\projects\\";
    private static final String[] extensions = 
    	{ "spring-petclinic", "wavsep", "bodgeit" };
	
    // TODO move relevant files to the src/test/resources folder and use that
	public static final String 
		PETCLINIC_SOURCE_LOCATION = testRoot + extensions[0],
		WAVSEP_SOURCE_LOCATION = testRoot + extensions[1],
		BODGEIT_SOURCE_LOCATION = testRoot + extensions[2],
		PETCLINIC_WEB_XML = PETCLINIC_SOURCE_LOCATION + "\\src\\main\\webapp\\WEB-INF\\web.xml",
		WAVSEP_WEB_XML = WAVSEP_SOURCE_LOCATION + "\\trunk\\WebContent\\WEB-INF\\web.xml",
		BODGEIT_WEB_XML = BODGEIT_SOURCE_LOCATION + "\\root\\WEB-INF\\web.xml"
		;
	
}
