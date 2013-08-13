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

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;

public class SpringParameterParsingTests {
	
	// These are immutable so it's ok to use the same one for all the tests
	static SpringModelParameterParser parser = new SpringModelParameterParser(
			new SpringEntityMappings(
			new File(TestConstants.PETCLINIC_SOURCE_LOCATION)));
	
	static SpringModelParameterParser[] allParsers = { parser, 
			new SpringModelParameterParser(null),
			new SpringModelParameterParser(new SpringEntityMappings(null)) };
	
	@Test
	public void testBasicModelParsing() {
		
		for (SpringModelParameterParser parser : allParsers) {
			// These are from the PetClinic Fortify results
			List<DataFlowElement> basicModelElements = Arrays.asList(
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
						"public String processFindForm(Owner owner, BindingResult result, Model model) {"),
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
						"Collection<Owner> results = this.clinicService.findOwnerByLastName(owner.getLastName());"),
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
						"Collection<Owner> results = this.clinicService.findOwnerByLastName(owner.getLastName());"),
				new DataFlowElement("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
						"return ownerRepository.findByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
						"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			Finding finding = new Finding();
			finding.setDataFlowElements(basicModelElements);
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of lastName", "lastName".equals(result));
		}
	}
	
	@Test
	public void testRequestParamParsing1() {
		
		for (SpringModelParameterParser parser : allParsers) {
			// These are doctored to test other methods of passing Spring parameters
			List<DataFlowElement> chainedRequestParamElements1 = Arrays.asList(
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(@RequestParam(\"testParam\") String lastName, Model model) {"),
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			Finding finding = new Finding();
			finding.setDataFlowElements(chainedRequestParamElements1);
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of testParam", "testParam".equals(result));
		}
	}
	
	@Test
	public void testRequestParamParsing2() {
		
		for (SpringModelParameterParser parser : allParsers) {
			// These are doctored to test other methods of passing Spring parameters
			List<DataFlowElement> chainedRequestParamElements2 = Arrays.asList(
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(@RequestParam String lastName, Model model) {"),
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			Finding finding = new Finding();
			finding.setDataFlowElements(chainedRequestParamElements2);
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of lastName", "lastName".equals(result));
		}
	}
	
	@Test
	public void testPathVariableParsing1() {
		for (SpringModelParameterParser parser : allParsers) {
			// These are doctored to test other methods of passing Spring parameters
			List<DataFlowElement> chainedPathVariableElements1 = Arrays.asList(
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(@PathVariable(\"testParam\") String lastName, Model model) {"),
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			Finding finding = new Finding();
			finding.setDataFlowElements(chainedPathVariableElements1);
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of testParam", "testParam".equals(result));
		}
	}
	
	@Test
	public void testPathVariableParsing2() {
		for (SpringModelParameterParser parser : allParsers) {
			// These are doctored to test other methods of passing Spring parameters
			List<DataFlowElement> pathVariableElements2 = Arrays.asList(
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(@PathVariable String lastName, Model model) {"),
				new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
				new DataFlowElement("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
				);
			
			Finding finding = new Finding();
			finding.setDataFlowElements(pathVariableElements2);
			
			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of lastName", "lastName".equals(result));
		}
	}
	
	@Test
	public void testChainedModelParsing() {
		
		// These are doctored to test a corner case
		List<DataFlowElement> chainedModelElements = Arrays.asList(
			new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
					"public String processFindForm(Pet pet, BindingResult result, Model model) {"),
			new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner().getLastName());"),
			new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
					"Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner().getLastName());"),
			new DataFlowElement("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
					"return ownerRepository.findByLastName(lastName);"),
			new DataFlowElement("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
					"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
			);
		
		Finding finding = new Finding();
		finding.setDataFlowElements(chainedModelElements);
		
		String result = parser.parse(finding);
		assertTrue("Parameter was " + result + " instead of owner.lastName", "owner.lastName".equals(result));
	}

	@Test
	public void testChainedMultiLevelModelParsing() {
		
		// These are doctored to test a corner case
		List<DataFlowElement> chainedMultiLevelModelElements = Arrays.asList(
			new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java",85,
				"public String processFindForm(Pet pet, BindingResult result, Model model) {"),
			new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
				"Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner());"),
			new DataFlowElement("java/org/springframework/samples/petclinic/web/OwnerController.java", 93,
				"Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner());"),
			new DataFlowElement("java/org/springframework/samples/petclinic/service/ClinicServiceImpl.java", 72,
				"return ownerRepository.findByLastName(owner.getLastName());"),
			new DataFlowElement("java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java", 84,
				"\"SELECT id, first_name, last_name, address, city, telephone FROM owners WHERE last_name like '\" + lastName + \"%'\",")
			);
		
		Finding finding = new Finding();
		finding.setDataFlowElements(chainedMultiLevelModelElements);
		
		
		String result = parser.parse(finding);
		assertTrue("Parameter was " + result + " instead of owner.lastName", "owner.lastName".equals(result));
	}

	@Test
	public void testNullInput() {
		
		for (SpringModelParameterParser parser : allParsers) {
			String result = parser.parse(null);
			assertTrue(result == null);
			
			Finding finding = new Finding();
			result = parser.parse(finding);
			assertTrue(result == null);
	
			List<DataFlowElement> elements = new ArrayList<DataFlowElement>();
			
			finding.setDataFlowElements(elements);
			result = parser.parse(finding);
			assertTrue(result == null);
			
			finding.getDataFlowElements().add(null);
			finding.getDataFlowElements().add(null);
			finding.getDataFlowElements().add(null);
			finding.getDataFlowElements().add(null);
			result = parser.parse(finding);
			assertTrue(result == null);
		}
	}

}
