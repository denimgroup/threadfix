////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import com.denimgroup.threadfix.framework.util.java.EntityParser;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.Set;

import static org.junit.Assert.assertTrue;

public class SpringEntityParserTests {
	
	@Nonnull
    File testFile = new File(TestConstants.PETCLINIC_SOURCE_LOCATION +
			TestConstants.SPRING_MODELS_PREFIX + TestConstants.SPRING_OWNER_MODEL);

	@Nonnull
	EntityParser parser = EntityParser.parse(testFile);
	
	@Test
	public void testBasicFieldEquivalence() {
		assertTrue("These should have been equal.",
				new ModelField("String", "address").equals(new ModelField("String", "address"))
				);
	}
	
	@Test
	public void testOwnerClassName() {
		assertTrue("Wrong class name. Expected Owner, got " + parser.getClassName(),
				"Owner".equals(parser.getClassName()));
	}
	
	@Test
	public void testOwnerExtends() {
		assertTrue("Wrong superclass name. Expected Person, got " + parser.getSuperClass(),
				"Person".equals(parser.getSuperClass()));
	}
	
	@Test
	public void testOwnerFields() {
		Set<ModelField> fieldMappings = parser.getFieldMappings();
		
		assertTrue("Model missed the address field.",
				fieldMappings.contains(new ModelField("String", "getAddress")));
		assertTrue("Model missed the city field.",
				fieldMappings.contains(new ModelField("String", "getCity")));
		assertTrue("Model missed the telephone field.",
				fieldMappings.contains(new ModelField("String", "getTelephone")));
		assertTrue("Model missed the pet field.",
				fieldMappings.contains(new ModelField("Pet", "getPet")));
	}
}
