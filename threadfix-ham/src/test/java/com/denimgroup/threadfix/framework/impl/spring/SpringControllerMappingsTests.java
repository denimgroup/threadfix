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

import java.io.File;

import org.junit.Test;

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.Endpoint;

public class SpringControllerMappingsTests {
	
	@Test
	public void printEndpoints() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringControllerMappings mappings = new SpringControllerMappings(file);
		
		for (Endpoint endpoint: mappings.generateEndpoints()) {
			System.out.println(endpoint);
		}
	}
	
	// This code validates that all the right controllers got in there and
	// that they have the correct number of associated endpoints.
	@Test
	public void testPetClinicControllerToUrls() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringControllerMappings mappings = new SpringControllerMappings(file);
		
		String controllersPrefix = "/src/main/java/org/springframework/samples/petclinic/web/";
		String[] controllerNames = { "CrashController.java", "OwnerController.java", "PetController.java",
			"VetController.java", "VisitController.java"
		};
		
		int[][] controllerIndexAndEndpointCount = {
			{ 0, 1 }, { 1, 7 }, { 2, 4 }, { 3, 1 }, { 4, 3 }
		};
		
		for (String controller : controllerNames) {
			assertTrue(controllersPrefix + controller + " was not a valid controller key.",
					!mappings.getEndpointsFromController(controllersPrefix + controller).isEmpty());
		}
		
		// validate that they have the right number of entries
		for (int[] element : controllerIndexAndEndpointCount) {
			assertTrue(mappings.getEndpointsFromController(
					controllersPrefix + controllerNames[element[0]]).size() ==
					element[1]);
		}
	}
	
	// This code validates that the URL -> Controller mapping is working correctly
	// that they have the correct number of associated endpoints.
	@Test
	public void testPetClinicUrlToControllers() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringControllerMappings mappings = new SpringControllerMappings(file);
		
		String[][] singleEndpoints = {
			{ "/owners/find", TestConstants.SPRING_OWNER_CONTROLLER },
			{ "/owners/{id}", TestConstants.SPRING_OWNER_CONTROLLER },
			{ "/owners", TestConstants.SPRING_OWNER_CONTROLLER },
			{ "/owners/{id}/pets/{id}/visits", TestConstants.SPRING_VISIT_CONTROLLER },
			{ "/vets", TestConstants.SPRING_VET_CONTROLLER },
			{ "/oups", TestConstants.SPRING_CRASH_CONTROLLER },
		};
		
		String[][] doubleEndpoints = {
			{ "/owners/new", TestConstants.SPRING_OWNER_CONTROLLER },
			{ "/owners/{id}/edit", TestConstants.SPRING_OWNER_CONTROLLER },
			{ "/owners/{id}/pets/new", TestConstants.SPRING_PET_CONTROLLER },
			{ "/owners/{id}/pets/{id}/edit", TestConstants.SPRING_PET_CONTROLLER },
			{ "/owners/{id}/pets/{id}/visits/new", TestConstants.SPRING_VISIT_CONTROLLER },
		};
		
		for (String[] singleEndpoint : singleEndpoints) {
			assertTrue(singleEndpoint + " should have had one endpoint, but had " +
					mappings.getEndpointsFromUrl(singleEndpoint[0]).size(),
					mappings.getEndpointsFromUrl(singleEndpoint[0]).size() == 1);
			
			String filePath = mappings.getEndpointsFromUrl(singleEndpoint[0])
					.iterator().next().getCleanedFilePath().replace('\\', '/');
			
			assertTrue("Expected " + singleEndpoint[1] + ", got " + filePath,
					filePath.equals(singleEndpoint[1]));
		}
		
		for (String[] doubleEndpoint : doubleEndpoints) {
			assertTrue(doubleEndpoint + " should have had two endpoints, but had " +
					mappings.getEndpointsFromUrl(doubleEndpoint[0]).size(),
					mappings.getEndpointsFromUrl(doubleEndpoint[0]).size() == 2);

			String filePath = mappings.getEndpointsFromUrl(doubleEndpoint[0])
					.iterator().next().getCleanedFilePath().replace('\\', '/');
			
			assertTrue("Expected + " + doubleEndpoint[1] + ", got " + filePath,
					filePath.equals(doubleEndpoint[1]));
		}
		
		assertTrue(mappings.getEndpointsFromController("").isEmpty());
		assertTrue(mappings.getEndpointsFromController(null).isEmpty());
		assertTrue(mappings.getEndpointsFromUrl("").isEmpty());
		assertTrue(mappings.getEndpointsFromUrl(null).isEmpty());
	}
	
	@Test
	public void testParameters() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringControllerMappings mappings = new SpringControllerMappings(file);
		
		String[][] paramSets = {
			{ "/owners", "lastName" },
		};
		
		for (String[] singleEndpoint : paramSets) {
			assertTrue(singleEndpoint[0] + " should have had the parameter " + singleEndpoint[1] + ", but only had " +
					mappings.getEndpointsFromUrl(singleEndpoint[0]).iterator().next().getParameters(),
					mappings.getEndpointsFromUrl(singleEndpoint[0]).iterator().next().getParameters().contains(singleEndpoint[1]));
		}
	}
	
	@Test
	public void testFakeFileInput() {
		File file = new File(TestConstants.FAKE_FILE);
		SpringControllerMappings mappings = new SpringControllerMappings(file);
		assertTrue(mappings.getEndpointsFromController("").isEmpty());
		assertTrue(mappings.getEndpointsFromController(null).isEmpty());
		assertTrue(mappings.getEndpointsFromUrl("").isEmpty());
		assertTrue(mappings.getEndpointsFromUrl(null).isEmpty());
	}

    @Test(expected= NullPointerException.class)
    public void testNullConstructorArgument() {
        new SpringControllerMappings(null);
    }
}
