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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.denimgroup.threadfix.framework.beans.CodePoint;
import com.denimgroup.threadfix.framework.beans.DefaultCodePoint;
import com.denimgroup.threadfix.framework.engine.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.EndpointQueryBuilder;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.framework.impl.jsp.JSPDataFlowParser;
import com.denimgroup.threadfix.framework.impl.jsp.JSPMappings;

public class JSPParameterParserTests {

	JSPDataFlowParser
		fullSourceParser = new JSPDataFlowParser(new JSPMappings(
			new File(TestConstants.BODGEIT_SOURCE_LOCATION)), SourceCodeAccessLevel.FULL),
		noSourceParser = new JSPDataFlowParser(null, SourceCodeAccessLevel.PARTIAL);
	
	// These are from the PetClinic Fortify results
	private static List<? extends CodePoint> basicModelElements = Arrays.asList(
		new DefaultCodePoint("root/register.jsp",32,
				"String username = (String) request.getParameter(\"username\");"),
		new DefaultCodePoint("root/register.jsp",32,
				"String username = (String) request.getParameter(\"username\");"),
		new DefaultCodePoint("root/register.jsp",60,
				" 	session.setAttribute(\"username\", username);"),
		new DefaultCodePoint("root/contact.jsp",33,
				"String username = (String) session.getAttribute(\"username\");"),
		new DefaultCodePoint("root/contact.jsp",33,
				"String username = (String) session.getAttribute(\"username\");"),
		new DefaultCodePoint("root/contact.jsp",115,
				"<input type=\"hidden\" id=\"user\" name=\"<%=username%>\" value=\"\"/>")
		);
	
	@Test
	public void testBasicNoSourceParsing() {
		EndpointQuery query = EndpointQueryBuilder.start().setCodePoints(basicModelElements).generateQuery();
		
		String result = noSourceParser.parse(query);
		assertTrue("Parameter was " + result + " instead of username", "username".equals(result));
	}
	
	@Test
	public void testBasicWithSourceParsing() {
		EndpointQuery query = EndpointQueryBuilder.start().setCodePoints(basicModelElements).generateQuery();
		
		String result = fullSourceParser.parse(query);
		assertTrue("Parameter was " + result + " instead of username", "username".equals(result));
	}
	
	@Test
	public void testNullInput() {
		EndpointQuery emptyDataFlowFinding = EndpointQueryBuilder.start().setCodePoints(new ArrayList<CodePoint>()).generateQuery();
		EndpointQuery nonEmptyDataFlowFinding = EndpointQueryBuilder.start().setCodePoints(basicModelElements).generateQuery();
		
		for (JSPDataFlowParser parser : new JSPDataFlowParser[] {fullSourceParser, noSourceParser}) {
			assertTrue("Parameter was not null and should have been.", parser.parse(null) == null);
			assertTrue("Parameter was not null and should have been.", parser.parse(EndpointQueryBuilder.start().generateQuery()) == null);
			assertTrue("Parameter was not null and should have been.", parser.parse(emptyDataFlowFinding) == null);
		}
		
		JSPMappings[] mappings = { null,
				new JSPMappings(null),
				new JSPMappings(new File(TestConstants.BODGEIT_SOURCE_LOCATION)) };

		for (JSPMappings mapping : mappings) {
			for (SourceCodeAccessLevel accessLevel : SourceCodeAccessLevel.values()) {
				JSPDataFlowParser parser = new JSPDataFlowParser(mapping, accessLevel);
				assertTrue("Parameter was not null and should have been.",
						parser.parse(null) == null);
				assertTrue("Parameter was not null and should have been.",
						parser.parse(EndpointQueryBuilder.start().generateQuery()) == null);
				assertTrue("Parameter was not null and should have been.",
						parser.parse(emptyDataFlowFinding) == null);
				assertTrue("Parameter was not username and should have been.",
						"username".equals(parser.parse(nonEmptyDataFlowFinding)));
			}
		}
		
	}
	
}
