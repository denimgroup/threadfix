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
package com.denimgroup.threadfix.framework.impl.jsp;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.Endpoint;

public class JSPMappingsTests {
	@NotNull
    String[] pages = { "/root/about.jsp",
			"/root/admin.jsp",
			"/root/advanced.jsp",
			"/root/basket.jsp",
			"/root/contact.jsp",
			"/root/footer.jsp",
			"/root/header.jsp",
			"/root/home.jsp",
			"/root/init.jsp",
			"/root/login.jsp",
			"/root/logout.jsp",
			"/root/password.jsp",
			"/root/product.jsp",
			"/root/register.jsp",
			"/root/score.jsp",
			"/root/search.jsp", };

	@Test
	public void testSize() {
		JSPMappings mappings = new JSPMappings(new File(
				TestConstants.BODGEIT_SOURCE_LOCATION));
		assertTrue("Size was " + mappings.generateEndpoints().size()
				+ " but should have been " + 13, mappings.generateEndpoints()
				.size() == 16);
	}

	@Test
	public void testKeys() {
		JSPMappings mappings = new JSPMappings(new File(
				TestConstants.BODGEIT_SOURCE_LOCATION));
		for (String page : pages) {
			assertTrue("Endpoint for " + page
					+ " shouldn't have been null but was.",
					mappings.getEndpoint(page) != null);
		}
	}

	@NotNull
    String[][] tests = { { "/root/advanced.jsp", "debug", "54" },
			{ "/root/advanced.jsp", "q", "58" },
			{ "/root/basket.jsp", "debug", "89" },
			{ "/root/basket.jsp", "update", "173" },
			{ "/root/basket.jsp", "productid", "174" },
			{ "/root/basket.jsp", "quantity", "178" }, };

	@Test
	public void testParameters() {
		JSPMappings mappings = new JSPMappings(new File(
				TestConstants.BODGEIT_SOURCE_LOCATION));
		for (String[] test : tests) {
			JSPEndpoint endpoint = mappings.getEndpoint(test[0]);
			int result = endpoint.getLineNumberForParameter(test[1]);
			assertTrue("Line number for " + test[0] + ": " + test[1]
					+ " should have been " + test[2] + ", but was " + result,
					Integer.valueOf(test[2]) == result);
		}
	}
	
	@Test
	public void testEndpointCSVCommas() {
		JSPMappings mappings = new JSPMappings(new File(
				TestConstants.BODGEIT_SOURCE_LOCATION));
		
		for (Endpoint endpoint : mappings.generateEndpoints()) {
			String csv = endpoint.getCSVLine();
			String toString = endpoint.toString();
			assertTrue("CSV was not equal to toString", csv.equals(toString));
			assertTrue("length of csv sections != 3", csv.split(",").length == 3);
		}
	}
}
