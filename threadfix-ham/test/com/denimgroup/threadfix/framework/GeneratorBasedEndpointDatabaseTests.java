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

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import com.denimgroup.threadfix.framework.enums.InformationSourceType;

public class GeneratorBasedEndpointDatabaseTests {
	
	private EndpointDatabase getSpringEndpointDatabase() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		
		return EndpointDatabaseFactory.getDatabase(file);
	}
	
	@Test
	public void testPetClinicDynamicToStaticPathQueries() {
		
		EndpointDatabase db = getSpringEndpointDatabase();
		
		for (String[] pair : dynamicToStaticTests) {
			String result = getStaticPath(db, pair[0]);
			assertTrue("Input: " + pair[0] + ", expected " + pair[1] + " but got " + result, result.equals(pair[1]));
		}
	}
	
	String[][] dynamicToStaticTests = new String[][] {
			{ "/owners", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners.html", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/{id}", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/3463", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/346323/edit", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/{id}/edit", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/find", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/new", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/3463", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/3463", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/owners/{id}/pets/{id}/visits/new", "/src/main/java/org/springframework/samples/petclinic/web/VisitController.java" },
			{ "/owners/5/pets/2/visits/new", "/src/main/java/org/springframework/samples/petclinic/web/VisitController.java" },
			{ "/owners/45683568/pets/6457247/visits/new", "/src/main/java/org/springframework/samples/petclinic/web/VisitController.java" },
			{ "/oups", "/src/main/java/org/springframework/samples/petclinic/web/CrashController.java" },
			{ "/oups.html", "/src/main/java/org/springframework/samples/petclinic/web/CrashController.java" },
			{ "/owners/{id}/pets/{id}/edit", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
			{ "/owners/5/pets/2/edit", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
			{ "/owners/24562/pets/345724824/edit", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
			{ "/vets", "/src/main/java/org/springframework/samples/petclinic/web/VetController.java" },
			{ "/owners/{id}/pets/new", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
			{ "/owners/36/pets/new", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
	};
	
	private String getStaticPath(EndpointDatabase db, String dynamicPath) {
		EndpointQuery query = EndpointQueryBuilder.start()
				.setInformationSourceType(InformationSourceType.DYNAMIC)
				.setDynamicPath(dynamicPath)
				.generateQuery();
		
		return db.findBestMatch(query).getFilePath();
	}
	
	@Test
	public void testHttpMethodRecognition() {
		EndpointDatabase db = getSpringEndpointDatabase();
		
		for (String[] httpMethodTest : httpMethodTests) {
			EndpointQuery query =
					EndpointQueryBuilder.start()
						.setDynamicPath(httpMethodTest[0])
						.setHttpMethod(httpMethodTest[1])
						.generateQuery();
			
			Endpoint result = db.findBestMatch(query);
			
			String currentQuery = httpMethodTest[0] + ": " + httpMethodTest[1];
			
			if (result == null) {
				assertTrue("No result was found, but line " + httpMethodTest[2] + " was expected for " + currentQuery,
						httpMethodTest[2] == null);
			} else {
				
				//String currentQuery = httpMethodTest[0] + ": " + httpMethodTest[1];
				
				assertTrue("Got an endpoint, but was not expecting one with " + currentQuery,
						httpMethodTest[2] != null);
				
				Integer value = Integer.valueOf(httpMethodTest[2]);
				
				assertTrue("Got " + result.getStartingLineNumber() + " but was expecting " + value + " with " + currentQuery,
						value.equals(result.getStartingLineNumber()));
			}
		}
	}
	
	String[][] httpMethodTests = new String[][] {
			{ "/owners/new", "GET", "60" },
			{ "/owners/new", "POST", "67" },
			{ "/owners/{id}/pets/{id}/edit", "GET", "85" },
			{ "/owners/{id}/pets/{id}/edit", "POST", "92" },
			{ "/owners/{id}/pets/{id}/edit", "PUT", "92" },
			{ "/owners/{id}/pets/new", "GET", "64" },
			{ "/owners/{id}/pets/new", "POST", "73" },
			{ "/oups", "GET", "33" },
			{ "/oups", "POST", null },
			{ "/owners/find", "GET", "78" },
			{ "/owners/find", "POST", null },
			{ "/owners/{id}/pets/{id}/visits", "GET", "79" },
			{ "/owners/{id}/pets/{id}/visits", "POST", null },
			{ "/owners/{id}/pets/{id}/visits/new", "GET", "59" },
			{ "/owners/{id}/pets/{id}/visits/new", "POST", "68" },
			{ "/owners/{id}/edit", "GET", "110" },
			{ "/owners/{id}/edit", "PUT", "117" },
			{ "/owners", "GET", "84" },
			{ "/owners", "POST", null },
	};
	
}
