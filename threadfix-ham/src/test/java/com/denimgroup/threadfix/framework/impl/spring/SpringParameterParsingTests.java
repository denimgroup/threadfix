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
import java.util.Arrays;
import java.util.List;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.Test;

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.DefaultCodePoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParserFactory;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;

public class SpringParameterParsingTests {
	
	@NotNull
    static ProjectConfig
		defaultConfig = new ProjectConfig(FrameworkType.SPRING_MVC, SourceCodeAccessLevel.FULL,
			new File(TestConstants.PETCLINIC_SOURCE_LOCATION), null),
		noSourceConfig = new ProjectConfig(FrameworkType.SPRING_MVC, SourceCodeAccessLevel.NONE,
				null, null);
	
	// These are immutable so it's ok to use the same one for all the tests
	@NotNull
    static SpringDataFlowParser parser = new SpringDataFlowParser(defaultConfig);
	@Nullable
    static ParameterParser factoryParser = ParameterParserFactory.getParameterParser(defaultConfig);
	
	@NotNull
    static ParameterParser[] allParsers = {
		factoryParser,
		parser,
		new SpringDataFlowParser(noSourceConfig) };
	
	@Test
	public void testBasicModelParsing() {
		
		for (ParameterParser parser : allParsers) {
			// These are from the PetClinic Fortify results
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
			
			EndpointQuery finding = EndpointQueryBuilder.start()
					.setCodePoints(basicModelElements)
					.generateQuery();
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of lastName", "lastName".equals(result));
		}
	}
	
	@Test
	public void testRequestParamParsing1() {
		
		for (ParameterParser parser : allParsers) {
			// These are doctored to test other methods of passing Spring parameters
			List<DefaultCodePoint> chainedRequestParamElements1 = Arrays.asList(
				new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(@RequestParam(\"testParam\") String lastName, Model model) {"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(lastName);"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			EndpointQuery finding = EndpointQueryBuilder.start()
					.setCodePoints(chainedRequestParamElements1)
					.generateQuery();
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of testParam", "testParam".equals(result));
		}
	}
	
	@Test
	public void testRequestParamParsing2() {
		
		for (ParameterParser parser : allParsers) {
			// These are doctored to test other methods of passing Spring parameters
			List<DefaultCodePoint> chainedRequestParamElements2 = Arrays.asList(
				new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(@RequestParam String lastName, Model model) {"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(lastName);"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			EndpointQuery finding = EndpointQueryBuilder.start()
					.setCodePoints(chainedRequestParamElements2)
					.generateQuery();
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of lastName", "lastName".equals(result));
		}
	}
	
	@Test
	public void testPathVariableParsing1() {
		for (ParameterParser parser : allParsers) {
			// These are doctored to test other methods of passing Spring parameters
			List<DefaultCodePoint> chainedPathVariableElements1 = Arrays.asList(
				new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(@PathVariable(\"testParam\") String lastName, Model model) {"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(lastName);"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			EndpointQuery finding = EndpointQueryBuilder.start()
					.setCodePoints(chainedPathVariableElements1)
					.generateQuery();
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of testParam", "testParam".equals(result));
		}
	}
	
	@Test
	public void testPathVariableParsing2() {
		for (ParameterParser parser : allParsers) {
			// These are doctored to test other methods of passing Spring parameters
			List<DefaultCodePoint> pathVariableElements2 = Arrays.asList(
				new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(@PathVariable String lastName, Model model) {"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(lastName);"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
				new DefaultCodePoint("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			EndpointQuery finding = EndpointQueryBuilder.start()
					.setCodePoints(pathVariableElements2)
					.generateQuery();
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of lastName", "lastName".equals(result));
		}
	}
	
	@Test
	public void testChainedModelParsing() {
		
		// These are doctored to test a corner case
		List<DefaultCodePoint> chainedModelElements = Arrays.asList(
			new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(Pet pet, BindingResult result, Model model) {"),
			new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner().getLastName());"),
			new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner().getLastName());"),
			new DefaultCodePoint("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
			new DefaultCodePoint("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
			);
		
		EndpointQuery finding = EndpointQueryBuilder.start()
				.setCodePoints(chainedModelElements)
				.generateQuery();
		
		String result = parser.parse(finding);
		assertTrue("Parameter was " + result + " instead of owner.lastName", "owner.lastName".equals(result));
	}

	@Test
	public void testChainedMultiLevelModelParsing() {
		
		// These are doctored to test a corner case
		List<DefaultCodePoint> chainedMultiLevelModelElements = Arrays.asList(
			new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
				"public String processFindForm(Pet pet, BindingResult result, Model model) {"),
			new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
				"Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner());"),
			new DefaultCodePoint("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
				"Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner());"),
			new DefaultCodePoint("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
				"return ownerRepository.findByLastName(owner.getLastName());"),
			new DefaultCodePoint("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
				"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
			);
		
		EndpointQuery finding = EndpointQueryBuilder.start()
				.setCodePoints(chainedMultiLevelModelElements)
				.generateQuery();
		
		String result = parser.parse(finding);
		assertTrue("Parameter was " + result + " instead of owner.lastName", "owner.lastName".equals(result));
	}

    @Test(expected= NullPointerException.class)
    public void testNullConstructorArg() {
        parser.parse(null);
    }
}
