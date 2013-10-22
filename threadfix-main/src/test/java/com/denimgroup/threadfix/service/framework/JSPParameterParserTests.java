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
import com.denimgroup.threadfix.service.merge.FrameworkType;
import com.denimgroup.threadfix.service.merge.MergeConfigurationGenerator;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;
import com.denimgroup.threadfix.service.merge.SourceCodeAccessLevel;
import com.denimgroup.threadfix.service.merge.VulnTypeStrategy;

public class JSPParameterParserTests {

	JSPDataFlowParser 
		fullSourceParser = new JSPDataFlowParser(new JSPMappings(
			new File(TestConstants.BODGEIT_SOURCE_LOCATION)), 
			new ScanMergeConfiguration(VulnTypeStrategy.EXACT, 
					SourceCodeAccessLevel.FULL, 
					FrameworkType.JSP, 
					null, 
					null, 
					null)),
		noSourceParser = new JSPDataFlowParser(null, new ScanMergeConfiguration(VulnTypeStrategy.EXACT, 
				SourceCodeAccessLevel.PARTIAL, 
				FrameworkType.JSP, 
				null, 
				null, 
				null));
	
	// These are from the PetClinic Fortify results
	private static List<DataFlowElement> basicModelElements = Arrays.asList(
		new DataFlowElement("root/register.jsp",32,
				"String username = (String) request.getParameter(\"username\");"),
		new DataFlowElement("root/register.jsp",32,
				"String username = (String) request.getParameter(\"username\");"),
		new DataFlowElement("root/register.jsp",60,
				" 	session.setAttribute(\"username\", username);"),
		new DataFlowElement("root/contact.jsp",33,
				"String username = (String) session.getAttribute(\"username\");"),
		new DataFlowElement("root/contact.jsp",33,
				"String username = (String) session.getAttribute(\"username\");"),
		new DataFlowElement("root/contact.jsp",115,
				"<input type=\"hidden\" id=\"user\" name=\"<%=username%>\" value=\"\"/>")
		);
	
	@Test
	public void testBasicNoSourceParsing() {
		Finding finding = new Finding();
		finding.setDataFlowElements(basicModelElements);
		
		String result = noSourceParser.parse(finding);
		assertTrue("Parameter was " + result + " instead of username", "username".equals(result));
	}
	
	@Test
	public void testBasicWithSourceParsing() {
		Finding finding = new Finding();
		finding.setDataFlowElements(basicModelElements);
		
		String result = fullSourceParser.parse(finding);
		assertTrue("Parameter was " + result + " instead of username", "username".equals(result));
	}
	
	@Test
	public void testNullInput() {
		Finding emptyDataFlowFinding = new Finding();
		emptyDataFlowFinding.setDataFlowElements(new ArrayList<DataFlowElement>());
		Finding nonEmptyDataFlowFinding = new Finding();
		nonEmptyDataFlowFinding.setDataFlowElements(basicModelElements);
		
		for (JSPDataFlowParser parser : new JSPDataFlowParser[] {fullSourceParser, noSourceParser}) {
			assertTrue("Parameter was not null and should have been.", parser.parse(null) == null);
			assertTrue("Parameter was not null and should have been.", parser.parse(new Finding()) == null);
			assertTrue("Parameter was not null and should have been.", parser.parse(emptyDataFlowFinding) == null);
		}
		
		JSPMappings[] mappings = { null, 
				new JSPMappings(null), 
				new JSPMappings(new File(TestConstants.BODGEIT_SOURCE_LOCATION)) };
		ScanMergeConfiguration [] configurations = {
				MergeConfigurationGenerator.getDefaultConfiguration(),
				new ScanMergeConfiguration(null, null, null, null, null, null),
				null
		};
		
		for (JSPMappings mapping : mappings) {
			for (ScanMergeConfiguration configuration : configurations) {
				JSPDataFlowParser parser = new JSPDataFlowParser(mapping, configuration);
				assertTrue("Parameter was not null and should have been.", 
						parser.parse(null) == null);
				assertTrue("Parameter was not null and should have been.", 
						parser.parse(new Finding()) == null);
				assertTrue("Parameter was not null and should have been.", 
						parser.parse(emptyDataFlowFinding) == null);
				assertTrue("Parameter was not username and should have been.", 
						"username".equals(parser.parse(nonEmptyDataFlowFinding)));
			}
		}
		
	}
	
}
