////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.impl.model.ModelFieldSet;
import com.denimgroup.threadfix.framework.util.java.EntityMappings;
import org.junit.Test;

import java.io.File;
import java.util.List;

import static org.junit.Assert.assertTrue;


public class SpringEntityMappingsTests {

	@Test
	public void testOwnerFields() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		EntityMappings mappings = new EntityMappings(file);
		
		ModelFieldSet ownerFields = mappings.getPossibleParametersForModelType("Owner");
		
		assertTrue(ownerFields != null);
		assertTrue(ownerFields.getField("lastName").getType().equals("String"));
		assertTrue(ownerFields.getField("firstName").getType().equals("String"));
		assertTrue(ownerFields.getField("address").getType().equals("String"));
		assertTrue(ownerFields.getField("city").getType().equals("String"));
		assertTrue(ownerFields.getField("telephone").getType().equals("String"));
		assertTrue(ownerFields.getField("id").getType().equals("Integer"));
	}
	
	@Test
	public void testPetFields() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		EntityMappings mappings = new EntityMappings(file);
		
		ModelFieldSet petFields = mappings.getPossibleParametersForModelType("Pet");
		
		assertTrue(petFields.getField("id").getType().equals("Integer"));
		assertTrue(petFields.getField("name").getType().equals("String"));
		assertTrue(petFields.getField("birthDate").getType().equals("DateTime"));
		assertTrue(petFields.getField("type.name").getType().equals("String"));
		
	}
	
	@Test
	public void testVetFields() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		EntityMappings mappings = new EntityMappings(file);
		
		ModelFieldSet vetFields = mappings.getPossibleParametersForModelType("Vet");
		
		assertTrue(vetFields.getField("lastName").getType().equals("String"));
		assertTrue(vetFields.getField("firstName").getType().equals("String"));
		assertTrue(vetFields.getField("id").getType().equals("Integer"));
		assertTrue(vetFields.getField("nrOfSpecialties").getType().equals("int"));
		
	}
	
	@Test
	public void testPetTypeFields() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		EntityMappings mappings = new EntityMappings(file);
		
		ModelFieldSet typeFields = mappings.getPossibleParametersForModelType("PetType");
		
		assertTrue(typeFields.getField("name").getType().equals("String"));
	}

	@Test
	public void testMethodChainResolution() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		EntityMappings mappings = new EntityMappings(file);
		
		List<ModelField> fields = mappings.getFieldsFromMethodCalls(".getOwner().getLastName()",
				new ModelField("Pet", "pet"));
		assertTrue(fields.get(0).equals(new ModelField("Pet", "pet")));
		assertTrue(fields.get(1).equals(new ModelField("Owner", "owner")));
		assertTrue(fields.get(2).equals(new ModelField("String", "lastName")));
		
		fields = mappings.getFieldsFromMethodCalls(".getOwner()",
				new ModelField("Pet", "pet"));
		assertTrue(fields.get(1).equals(new ModelField("Owner", "owner")));
		
		fields = mappings.getFieldsFromMethodCalls(".getLastName()",
				new ModelField("Owner", "owner"));
		assertTrue(fields.get(1).equals(new ModelField("String", "lastName")));
	}
	
	@Test
	public void testFakeFile() {
		File file = new File(TestConstants.FAKE_FILE);
		EntityMappings mappings = new EntityMappings(file);
		
		List<ModelField> fields = mappings.getFieldsFromMethodCalls(".getOwner().getLastName()",
				new ModelField("Pet", "pet"));
		assertTrue(fields.get(0).equals(new ModelField("Pet", "pet")));
		assertTrue(fields.size() == 1);
		
		fields = mappings.getFieldsFromMethodCalls(".getOwner()",
				new ModelField("Pet", "pet"));
		assertTrue(fields.size() == 1);
		assertTrue(fields.get(0).equals(new ModelField("Pet", "pet")));
		
		fields = mappings.getFieldsFromMethodCalls(".getLastName()",
				new ModelField("Owner", "owner"));
		assertTrue(fields.size() == 1);
		assertTrue(fields.get(0).equals(new ModelField("Owner", "owner")));
	}
}
