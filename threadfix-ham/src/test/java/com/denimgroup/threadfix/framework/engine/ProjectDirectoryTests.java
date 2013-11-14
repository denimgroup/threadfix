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
package com.denimgroup.threadfix.framework.engine;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

import com.denimgroup.threadfix.framework.TestConstants;

public class ProjectDirectoryTests {
	
	@NotNull
    ProjectDirectory
		springDirectory = new ProjectDirectory(new File(TestConstants.PETCLINIC_SOURCE_LOCATION));
	
	@Test
	public void testMultipleMatchResolution() {
		String[][] tests = {
			{ "/mysql/initDB.sql", "/src/main/resources/db/mysql/initDB.sql" },
			{ "/hsqldb/initDB.sql", "/src/main/resources/db/hsqldb/initDB.sql" },
		};
		
		for (String[] test : tests) {
			File file = springDirectory.findFile(test[0]);
			
			String result = springDirectory.findCanonicalFilePath(file.getAbsolutePath());

			assertTrue("Found " + result + " results instead of " + test[1] + " for " + test[0],
					test[1].equals(result));
		}
	}

	@Test
	public void testStarFilePaths() {
		Object[][] tests = {
				{ "po*.xml", 1 },
				{ "*Entity.java", 2 },
				{ "ClinicService*.java", 5},
				{ "*Controller*", 5 },
				{ "A*st*act*li*icSe*ice*t*ava", 1 }
			};
		
		for (Object[] test : tests) {
			int numResults = springDirectory.findFiles((String) test[0]).size();
			assertTrue("Found " + numResults + " results instead of " + test[1] + " for " + test[0],
					numResults == (int) test[1]);
		}
	}
	
	@Test
	public void testCanonicalRoot() {
		String[][] tests = {
				{ "/User/test/scratch/some/directory/petclinic/src/main/resources/db/mysql/initDB.sql", "/src/main/resources/db/mysql/initDB.sql" },
				{ "/User/test/scratch/some/directory/petclinic/pom.xml", "/pom.xml" },
				{ "/User/test/scratch/some/directory/petclinic/src/main/resources/ehcache.xml", "/src/main/resources/ehcache.xml" },
		};
		
		String root = "/User/test/scratch/some/directory/";
		
		for (String[] test : tests) {
			String result = springDirectory.findCanonicalFilePath(test[0], root);
			assertTrue("Found " + result + " instead of " + test[1] + " for " + test[0],
					test[1].equals(result));
		}
	}
	
	
	
}
