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
package com.denimgroup.threadfix.framework.impl.spring;

import static org.junit.Assert.assertTrue;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;

public class SpringPathCleanerTests {
	
	@NotNull
    String[][] petClinicAppScanData = {
		{ "/petclinic", ""},
		{ "/petclinic/owners", "/owners" },
		{ "/petclinic/owners/2/pets/new", "/owners/{id}/pets/new" },
		{ "/petclinic/owners/357/edit", "/owners/{id}/edit" },
		{ "/petclinic/owners/835/pets", "/owners/{id}/pets" },
		{ "/petclinic/owners/83/pets/new", "/owners/{id}/pets/new" },
		{ "/petclinic/owners/26/pets/26/visits/new", "/owners/{id}/pets/{id}/visits/new" },
		{ "/petclinic/owners/26;jsessionid=2623573468245848356853", "/owners/{id}" },
		{ "/petclinic/owners/26/test;jsessionid=2623573468245848356853", "/owners/{id}/test" },
	};
	
	@Test
	public void dynamicTest() {
		String dynamicRoot = "/petclinic", staticRoot = "";
		
		PathCleaner cleaner = new SpringPathCleaner(dynamicRoot, staticRoot);
		
		System.out.println(cleaner);
		
		assertTrue("Didn't save dynamic root correctly", cleaner.getDynamicRoot().equals(dynamicRoot));
		assertTrue("Didn't save static root correctly", cleaner.getStaticRoot().equals(staticRoot));
		
		for (String[] test : petClinicAppScanData) {
			String testDescription = test[0] + " => " + test[1];
			String result = cleaner.cleanDynamicPath(test[0]);
			
			assertTrue("Got " + result + " for test " + testDescription,
					result.equals(test[1]));
		}
	}

	@NotNull
    String[][] petClinicFortifyData = {
		{ TestConstants.PETCLINIC_SOURCE_LOCATION + "/src/main/java/test/Controller.java", "/src/main/java/test/Controller.java"},
		{ TestConstants.PETCLINIC_SOURCE_LOCATION + "/pom.xml", "/pom.xml"},
	};
	
	@Test
	public void staticTest() {
		String dynamicRoot = "/petclinic", staticRoot = TestConstants.PETCLINIC_SOURCE_LOCATION;
		
		PathCleaner cleaner = new SpringPathCleaner(dynamicRoot, staticRoot);
		
		System.out.println(cleaner);
		
		assertTrue("Didn't save dynamic root correctly", cleaner.getDynamicRoot().equals(dynamicRoot));
		assertTrue("Didn't save static root correctly", cleaner.getStaticRoot().equals(staticRoot));
		
		for (String[] test : petClinicFortifyData) {
			String testDescription = test[0] + " => " + test[1];
			String result = cleaner.cleanStaticPath(test[0]);
			
			assertTrue("Got " + result + " for test " + testDescription,
					result.equals(test[1]));
		}
	}

    @Test(expected= NullPointerException.class)
    public void nullTests() {
        new SpringPathCleaner("/petclinic", "").cleanDynamicPath(null);
    }

    @Test(expected= NullPointerException.class)
    public void nullTests2() {
        new SpringPathCleaner("/petclinic", "").cleanStaticPath(null);
    }
}
