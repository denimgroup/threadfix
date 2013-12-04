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
import java.util.Set;

import org.jetbrains.annotations.NotNull;
import org.junit.Ignore;
import org.junit.Test;

import com.denimgroup.threadfix.framework.ResourceManager;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.Endpoint;

public class SpringControllerEndpointParserTests {
	
	@NotNull
    String[][] expected = {
			{"/owners/new", "GET",  "45", "49" },
			{"/owners/new", "POST", "52", "60" },
			{"/owners/find", "GET", "63", "66" },
			{"/owners",      "GET", "69", "92" },
			{"/owners/{id}/edit", "GET", "95", "99"},
			{"/owners/{id}/edit", "PUT", "102", "110"},
			{"/owners/{id}", "POST", "119", "123"}, // with no explicit method, it refers to the class annotation
			{"/owners/multiple/methods", "GET", "126", "130"},
			{"/owners/multiple/methods", "POST", "126", "130"},
	};

	@Test
	public void testClassAnnotation() {
		SpringEntityMappings mappings = new SpringEntityMappings(new File(TestConstants.PETCLINIC_SOURCE_LOCATION));
		
		File file = ResourceManager.getSpringFile(TestConstants.SPRING_CONTROLLER_WITH_CLASS_REQUEST_MAPPING);
		
		Set<? extends Endpoint> endpoints =
				SpringControllerEndpointParser.parse(file, mappings);
		
		assertTrue("File wasn't found", file != null);
		assertTrue("File didn't exist at " + file.getAbsolutePath(), file.exists());
		
		for (String[] test : expected) {
			boolean matches = false;
			
			int start = Integer.valueOf(test[2]);
			int end   = Integer.valueOf(test[3]);
			
			for (Endpoint endpoint : endpoints) {
				if (endpoint.getUrlPath().equals(test[0])) {
					if (endpoint.getHttpMethods().contains(test[1])) {
                        matches = true;

						for (int i = start; i < end; i ++) {
							if (!endpoint.matchesLineNumber(i)) {
                                System.out.println("Broke on " + i);
                                matches = false;
                                break;
							}
						}

                        if (!matches) {
						    break;
                        }
					}
				}
			}
			
			assertTrue(" Unable to match for " + test[0] + "," + test[1] + "," +
							test[2] + "," + test[3], matches);
			
		}
		
	}

}
