////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.framework;

import java.net.URISyntaxException;

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
		BODGEIT_WEB_XML = BODGEIT_SOURCE_LOCATION + "\\root\\WEB-INF\\web.xml",
		BASE_DISPATCHER_FOLDER = getResourcePath("SupportingFiles\\Code"),
		MVC_DISPATCHER_1 = BASE_DISPATCHER_FOLDER + "\\dispatcher-mvc.xml",
		MVC_DISPATCHER_2 = BASE_DISPATCHER_FOLDER + "\\dispatcher-not-mvc.xml",
		FAKE_FILE = "",
		SPRING_CONTROLLERS_PREFIX = "/src/main/java/org/springframework/samples/petclinic/web/",
		SPRING_CRASH_CONTROLLER = SPRING_CONTROLLERS_PREFIX + "CrashController.java",
		SPRING_OWNER_CONTROLLER = SPRING_CONTROLLERS_PREFIX + "OwnerController.java",
		SPRING_PET_CONTROLLER   = SPRING_CONTROLLERS_PREFIX + "PetController.java",
		SPRING_VET_CONTROLLER   = SPRING_CONTROLLERS_PREFIX + "VetController.java",
		SPRING_VISIT_CONTROLLER = SPRING_CONTROLLERS_PREFIX + "VisitController.java"
		;
	
	private static String getResourcePath(String input) {
		try {
			return TestConstants.class.getClassLoader().getResource("SupportingFiles/Code").toURI().toString().substring(5);
		} catch (URISyntaxException e) {
			e.printStackTrace();
			return "";
		}
	}
}
