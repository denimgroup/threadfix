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
package com.denimgroup.threadfix.framework;


public class TestConstants {
	private TestConstants(){}
	
	private static final String testRoot = "/Users/mac/scratch/projects/";
    private static final String[] extensions =
    	{ "petclinic", "wavsep", "bodgeit" };
	
    // TODO move relevant files to the src/test/resources folder and use that
	public static final String
		PETCLINIC_SOURCE_LOCATION = testRoot + extensions[0],
		WAVSEP_SOURCE_LOCATION = testRoot + extensions[1],
		BODGEIT_SOURCE_LOCATION = testRoot + extensions[2],
		BODGEIT_JSP_ROOT = BODGEIT_SOURCE_LOCATION + "/root",
		PETCLINIC_WEB_XML = PETCLINIC_SOURCE_LOCATION + "/src/main/webapp/WEB-INF/web.xml",
		WAVSEP_WEB_XML = WAVSEP_SOURCE_LOCATION + "/trunk/WebContent/WEB-INF/web.xml",
		BODGEIT_WEB_XML = BODGEIT_JSP_ROOT + "/WEB-INF/web.xml",
		FAKE_FILE = "",
		SPRING_CONTROLLERS_PREFIX = "/src/main/java/org/springframework/samples/petclinic/web/",
		SPRING_CRASH_CONTROLLER = SPRING_CONTROLLERS_PREFIX + "CrashController.java",
		SPRING_OWNER_CONTROLLER = SPRING_CONTROLLERS_PREFIX + "OwnerController.java",
		SPRING_PET_CONTROLLER   = SPRING_CONTROLLERS_PREFIX + "PetController.java",
		SPRING_VET_CONTROLLER   = SPRING_CONTROLLERS_PREFIX + "VetController.java",
		SPRING_VISIT_CONTROLLER = SPRING_CONTROLLERS_PREFIX + "VisitController.java",
		SPRING_MODELS_PREFIX = "/src/main/java/org/springframework/samples/petclinic/model/",
		SPRING_OWNER_MODEL = "Owner.java",
		SPRING_CONTROLLER_WITH_CLASS_REQUEST_MAPPING = "ControllerWithClassAnnotation.java.txt"
		;
}
