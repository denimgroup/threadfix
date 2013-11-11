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
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.InformationSourceType;

public class PetClinicEndpointDatabaseTests {
	
	private EndpointDatabase getSpringEndpointDatabase() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		
		return EndpointDatabaseFactory.getDatabase(file, FrameworkType.SPRING_MVC, new SpringPathCleaner("/petclinic", null));
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
			{ "/petclinic/owners", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners.html", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/{id}", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/3463", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/346323/edit", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/{id}/edit", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/find", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/new", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/3463", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/3463", "/src/main/java/org/springframework/samples/petclinic/web/OwnerController.java" },
			{ "/petclinic/owners/{id}/pets/{id}/visits/new", "/src/main/java/org/springframework/samples/petclinic/web/VisitController.java" },
			{ "/petclinic/owners/5/pets/2/visits/new", "/src/main/java/org/springframework/samples/petclinic/web/VisitController.java" },
			{ "/petclinic/owners/45683568/pets/6457247/visits/new", "/src/main/java/org/springframework/samples/petclinic/web/VisitController.java" },
			{ "/petclinic/oups", "/src/main/java/org/springframework/samples/petclinic/web/CrashController.java" },
			{ "/petclinic/oups.html", "/src/main/java/org/springframework/samples/petclinic/web/CrashController.java" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
			{ "/petclinic/owners/5/pets/2/edit", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
			{ "/petclinic/owners/24562/pets/345724824/edit", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
			{ "/petclinic/vets", "/src/main/java/org/springframework/samples/petclinic/web/VetController.java" },
			{ "/petclinic/owners/{id}/pets/new", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
			{ "/petclinic/owners/36/pets/new", "/src/main/java/org/springframework/samples/petclinic/web/PetController.java" },
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
			{ "/petclinic/owners/new", "GET", "60" },
			{ "/petclinic/owners/new", "POST", "67" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "GET", "85" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "POST", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "PUT", "92" },
			{ "/petclinic/owners/{id}/pets/new", "GET", "64" },
			{ "/petclinic/owners/{id}/pets/new", "POST", "73" },
			{ "/petclinic/oups", "GET", "33" },
			{ "/petclinic/oups", "POST", null },
			{ "/petclinic/owners/find", "GET", "78" },
			{ "/petclinic/owners/find", "POST", null },
			{ "/petclinic/owners/{id}/pets/{id}/visits", "GET", "79" },
			{ "/petclinic/owners/{id}/pets/{id}/visits", "POST", null },
			{ "/petclinic/owners/{id}/pets/{id}/visits/new", "GET", "59" },
			{ "/petclinic/owners/{id}/pets/{id}/visits/new", "POST", "68" },
			{ "/petclinic/owners/{id}/edit", "GET", "110" },
			{ "/petclinic/owners/{id}/edit", "PUT", "117" },
			{ "/petclinic/owners", "GET", "84" },
			{ "/petclinic/owners", "POST", null },
	};
	
}
