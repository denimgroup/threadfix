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

import java.io.File;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Test;

public class SpringControllerMappingsTests {
	
	// test code for petclinic
	// This code validates that all the right controllers got in there and 
	// that they have the correct number of associated endpoints.
	@Test
	public void main() {
		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
		
		SpringControllerMappings mappings = new SpringControllerMappings(file);
		
		Set<SpringControllerEndpoint> set = new TreeSet<>();
		
		for (Entry<String, Set<SpringControllerEndpoint>> entry : mappings.urlToControllerMethodsMap.entrySet()) {
			set.addAll(entry.getValue());
		}
		
		String controllersPrefix = "\\src\\main\\java\\org\\springframework\\samples\\petclinic\\web\\";
		String[] controllerNames = { "CrashController.java", "OwnerController.java", "PetController.java",
			"VetController.java", "VisitController.java"
		};
		
		int[][] lengths = {
			{ 0, 1 }, { 1, 7 }, { 2, 4 }, { 3, 1 }, { 4, 3 }
		};
		
		assert(mappings.urlToControllerMethodsMap.size() == controllerNames.length);
		
		for (String controller : controllerNames) {
			assert(mappings.urlToControllerMethodsMap.containsKey(controllersPrefix + controller));
		}
		
		// validate that they have the right number of entries
		for (int i = 0; i < lengths.length; i ++) {
			assert(mappings.urlToControllerMethodsMap.get(
					controllersPrefix + controllerNames[lengths[i][0]]).size() == lengths[i][1]);
		}
	}
	
}
