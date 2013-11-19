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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.DefaultCodePoint;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
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
	
	@Nullable
    private EndpointDatabase getSpringEndpointDatabaseDynamic() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		
		return EndpointDatabaseFactory.getDatabase(file, FrameworkType.SPRING_MVC, new SpringPathCleaner("/petclinic", null));
	}
	
	@Test
	public void testPetClinicDynamicToStaticPathQueries() {
		
		EndpointDatabase db = getSpringEndpointDatabaseDynamic();
		
		for (String[] pair : dynamicToStaticTests) {
			String result = getStaticPath(db, pair[0]);
			assertTrue("Input: " + pair[0] + ", expected " + pair[1] + " but got " + result, result.equals(pair[1]));
		}
	}
	
	@NotNull
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
	
	@NotNull
    private String getStaticPath(@NotNull EndpointDatabase db, String dynamicPath) {
		EndpointQuery query = EndpointQueryBuilder.start()
				.setInformationSourceType(InformationSourceType.DYNAMIC)
				.setDynamicPath(dynamicPath)
				.generateQuery();
		
		return db.findBestMatch(query).getFilePath();
	}
	
	@NotNull
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


    @Nullable
    private EndpointDatabase getSpringEndpointDatabaseStatic() {
        File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);

        return EndpointDatabaseFactory.getDatabase(file, FrameworkType.SPRING_MVC, new SpringPathCleaner("/petclinic", null));
    }

	@Test
	public void testHttpMethodRecognition() {
		EndpointDatabase db = getSpringEndpointDatabaseStatic();
		
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
	
	@NotNull
    String[][] parameterTests = new String[][] {
			{ "/petclinic/owners/new", null, "60" },
			{ "/petclinic/owners/new", "any-other-param", null },
			{ "/petclinic/owners/new", "lastName", "67" },
			{ "/petclinic/owners/new", "pet.type", "67" },
			{ "/petclinic/owners/new", "city", "67" },
			{ "/petclinic/owners/new", "id", "67" },
			{ "/petclinic/owners/new", "firstName", "67" },
			{ "/petclinic/owners/new", "telephone", "67" },
			{ "/petclinic/owners/new", "pet.type.id", "67" },
			{ "/petclinic/owners/new", "pet.name", "67" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "petId", "85" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "GET", null },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.type", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.pet.type.id", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.city", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.pet.type.name", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "type", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.firstName", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.id", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "id", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.id", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.id", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.telephone", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.pet.owner", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "name", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "type.name", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.address", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.firstName", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "birthDate", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.city", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.pet.name", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.birthDate", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.pet.id", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.lastName", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.type.id", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.pet.type", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.name", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.type.name", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.telephone", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.address", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "owner.pet.owner.pet.birthDate", "92" },
			{ "/petclinic/owners/{id}/pets/{id}/edit", "type.id", "92" },
			{ "/petclinic/owners/{id}/pets/new", null, null },
			{ "/petclinic/owners/{id}/pets/new", "ownerId", "64" },
			{ "/petclinic/owners/{id}/pets/new", "owner.pet.birthDate", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.pet.type", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.city", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.lastName", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.pet.type.id", "73" },
			{ "/petclinic/owners/{id}/pets/new", "type", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.pet.name", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.id", "73" },
			{ "/petclinic/owners/{id}/pets/new", "id", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.pet", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.pet.type.name", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.telephone", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.pet.id", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.address", "73" },
			{ "/petclinic/owners/{id}/pets/new", "name", "73" },
			{ "/petclinic/owners/{id}/pets/new", "type.name", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner", "73" },
			{ "/petclinic/owners/{id}/pets/new", "owner.firstName", "73" },
			{ "/petclinic/owners/{id}/pets/new", "birthDate", "73" },
			{ "/petclinic/owners/{id}/pets/new", "type.id", "73" },
			{ "/petclinic/oups", "any", null },
			{ "/petclinic/oups", null, "33" },
	};

    // TODO add parameter stuff
    @Test
    public void testParameterRecognition() {
        EndpointDatabase db = getSpringEndpointDatabaseStatic();

        for (String[] httpMethodTest : parameterTests) {
            EndpointQuery query =
                    EndpointQueryBuilder.start()
                            .setDynamicPath(httpMethodTest[0])
                            .setParameter(httpMethodTest[1])
                            .generateQuery();

            Endpoint result = db.findBestMatch(query);

            String currentQuery = httpMethodTest[0] + ": " + httpMethodTest[1];

            if (result == null) {
                assertTrue("No result was found, but line " + httpMethodTest[2] + " was expected for " + currentQuery,
                        httpMethodTest[2] == null);
            } else {
                assertTrue("Got an endpoint, but was not expecting one with " + currentQuery,
                        httpMethodTest[2] != null);

                Integer value = Integer.valueOf(httpMethodTest[2]);

                assertTrue("Got " + result.getStartingLineNumber() + " but was expecting " + value + " with " + currentQuery,
                        value.equals(result.getStartingLineNumber()));
            }
        }
    }

    List<? extends CodePoint> basicModelElements = Arrays.asList(
            new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
                    "public String processFindForm(Owner owner, BindingResult result, Model model) {"),
            new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
                    "Collection<Owner> results = this.clinicService.findOwnerByLastName(owner.getLastName());"),
            new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
                    "Collection<Owner> results = this.clinicService.findOwnerByLastName(owner.getLastName());"),
            new DefaultCodePoint("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
                    "return ownerRepository.findByLastName(lastName);"),
            new DefaultCodePoint("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
                    "\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
    );

    // TODO add parameter stuff
    @Test
    public void testCodePoints() {
        EndpointDatabase db = getSpringEndpointDatabaseStatic();

        EndpointQuery query = EndpointQueryBuilder.start()
                .setCodePoints(basicModelElements)
                .setStaticPath("java/org/springframework/samples/petclinic/repository/jpa/JpaOwnerRepositoryImpl.java")
                .generateQuery();

        Endpoint result = db.findBestMatch(query);

        assertTrue("Result was null!", result != null);
    }

	
	
}
