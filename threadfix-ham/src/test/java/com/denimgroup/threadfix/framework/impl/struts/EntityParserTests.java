////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.impl.struts;

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.util.java.EntityParser;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.Set;

import static org.junit.Assert.assertTrue;

public class EntityParserTests {
	
	@Nonnull
    File testFile = new File("C:/SourceCode/roller-weblogger-5.1.1-source"
            +"/app/src/main/java/org/apache/roller/weblogger/ui/rendering/model/SearchResultsModel.java");

	@Nonnull
	EntityParser parser = EntityParser.parse(testFile);
	
	@Test
	public void testBasicFieldEquivalence() {
		assertTrue("These should have been equal.",
				new ModelField("String", "term").equals(new ModelField("String", "term"))
				);
	}
	
	@Test
	public void testSearchResultsModelClassName() {
		assertTrue("Wrong class name. Expected SearchResultsModel, got " + parser.getClassName(),
				"SearchResultsModel".equals(parser.getClassName()));
	}
	
	@Test
	public void testSearchResultsModelExtends() {
		assertTrue("Wrong superclass name. Expected Person, got " + parser.getSuperClass(),
				"PageModel".equals(parser.getSuperClass()));
	}
	
	@Test
	public void testSearchResultsModelFields() {
		Set<ModelField> fieldMappings = parser.getFieldMappings();
		
		assertTrue("Model missed the term field.",
				fieldMappings.contains(new ModelField("String", "getTerm")));
		assertTrue("Model missed the raw term field.",
				fieldMappings.contains(new ModelField("String", "getRawTerm")));
		assertTrue("Model missed the hits field.",
				fieldMappings.contains(new ModelField("int", "getHits")));
		assertTrue("Model missed the WeblogEntriesPager field.",
				fieldMappings.contains(new ModelField("WeblogEntriesPager", "getWeblogEntriesPager")));
	}
}
