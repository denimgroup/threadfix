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
import java.util.List;

import org.junit.Test;

import com.denimgroup.threadfix.framework.TestConstants;


public class SpringEntityMappingsTests {

	@Test
	public void testOwnerFields() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringEntityMappings mappings = new SpringEntityMappings(file);
		
		BeanFieldSet ownerFields = mappings.getPossibleParametersForModelType("Owner");
		
		assertTrue(ownerFields != null);
		assertTrue(ownerFields.getField("lastName").getType().equals("String"));
		assertTrue(ownerFields.getField("firstName").getType().equals("String"));
		assertTrue(ownerFields.getField("address").getType().equals("String"));
		assertTrue(ownerFields.getField("city").getType().equals("String"));
		assertTrue(ownerFields.getField("telephone").getType().equals("String"));
		assertTrue(ownerFields.getField("pet").getType().equals("Pet"));
		assertTrue(ownerFields.getField("id").getType().equals("Integer"));
	}
	
	@Test
	public void testPetFields() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringEntityMappings mappings = new SpringEntityMappings(file);
		
		BeanFieldSet petFields = mappings.getPossibleParametersForModelType("Pet");
		
		assertTrue(petFields.getField("id").getType().equals("Integer"));
		assertTrue(petFields.getField("name").getType().equals("String"));
		assertTrue(petFields.getField("birthDate").getType().equals("DateTime"));
		assertTrue(petFields.getField("owner").getType().equals("Owner"));
		assertTrue(petFields.getField("type").getType().equals("PetType"));
		
	}
	
	@Test
	public void testVetFields() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringEntityMappings mappings = new SpringEntityMappings(file);
		
		BeanFieldSet vetFields = mappings.getPossibleParametersForModelType("Vet");
		
		assertTrue(vetFields.getField("lastName").getType().equals("String"));
		assertTrue(vetFields.getField("firstName").getType().equals("String"));
		assertTrue(vetFields.getField("id").getType().equals("Integer"));
		assertTrue(vetFields.getField("nrOfSpecialties").getType().equals("int"));
		
	}
	
	@Test
	public void testPetTypeFields() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringEntityMappings mappings = new SpringEntityMappings(file);
		
		BeanFieldSet typeFields = mappings.getPossibleParametersForModelType("PetType");
		
		assertTrue(typeFields.getField("name").getType().equals("String"));
	}

	@Test
	public void testMethodChainResolution() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		SpringEntityMappings mappings = new SpringEntityMappings(file);
		
		List<BeanField> fields = mappings.getFieldsFromMethodCalls(".getOwner().getLastName()",
				new BeanField("Pet", "pet"));
		assertTrue(fields.get(0).equals(new BeanField("Pet", "pet")));
		assertTrue(fields.get(1).equals(new BeanField("Owner", "owner")));
		assertTrue(fields.get(2).equals(new BeanField("String", "lastName")));
		
		fields = mappings.getFieldsFromMethodCalls(".getOwner()",
				new BeanField("Pet", "pet"));
		assertTrue(fields.get(1).equals(new BeanField("Owner", "owner")));
		
		fields = mappings.getFieldsFromMethodCalls(".getLastName()",
				new BeanField("Owner", "owner"));
		assertTrue(fields.get(1).equals(new BeanField("String", "lastName")));
	}
	
	@Test
	public void testFakeFile() {
		File file = new File(TestConstants.FAKE_FILE);
		SpringEntityMappings mappings = new SpringEntityMappings(file);
		
		List<BeanField> fields = mappings.getFieldsFromMethodCalls(".getOwner().getLastName()",
				new BeanField("Pet", "pet"));
		assertTrue(fields.get(0).equals(new BeanField("Pet", "pet")));
		assertTrue(fields.size() == 1);
		
		fields = mappings.getFieldsFromMethodCalls(".getOwner()",
				new BeanField("Pet", "pet"));
		assertTrue(fields.size() == 1);
		assertTrue(fields.get(0).equals(new BeanField("Pet", "pet")));
		
		fields = mappings.getFieldsFromMethodCalls(".getLastName()",
				new BeanField("Owner", "owner"));
		assertTrue(fields.size() == 1);
		assertTrue(fields.get(0).equals(new BeanField("Owner", "owner")));
	}

    @Test(expected= NullPointerException.class)
    public void testNullConstructorArgument() {
        new SpringEntityMappings(null);
    }
}
