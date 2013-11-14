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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.impl.jsp.JSPIncludeParser;

// TODO add more tests
public class JSPIncludeParserTests {
	
	@NotNull
    static Map<String, Set<String>> samples = new HashMap<>();
	@NotNull
    static String[][] sampleStrings = {
		{ // this tests the <%@ include file="include.jsp"%> style
			TestConstants.WAVSEP_SOURCE_LOCATION + "/trunk/WebContent/active/LFI-Detection-Evaluation-GET-404Error/Case49-LFI-ContextStream-FilenameContext-UnixTraversalValidation-OSPath-DefaultFullInput-SlashPathReq-Read.jsp",
			TestConstants.WAVSEP_SOURCE_LOCATION + "/trunk/WebContent/active/LFI-Detection-Evaluation-GET-404Error/inclusion-logic.jsp",
			TestConstants.WAVSEP_SOURCE_LOCATION + "/trunk/WebContent/active/LFI-Detection-Evaluation-GET-404Error/include.jsp"
		},
		{ // This tests the <jsp:include page="/header.jsp"/> style
			TestConstants.BODGEIT_SOURCE_LOCATION + "/root/basket.jsp",
			TestConstants.BODGEIT_SOURCE_LOCATION + "/root/header.jsp",
			TestConstants.BODGEIT_SOURCE_LOCATION + "/root/footer.jsp",
		}
	};
	
	static {
		for (String[] stringSet : sampleStrings) {
			add(stringSet);
		}
	}
	
	private static void add(@NotNull String[] stuff) {
		Set<String> strings = new HashSet<>();
		for (int i = 1; i < stuff.length; i++) {
			strings.add(stuff[i]);
		}
		samples.put(stuff[0], strings);
	}

	@Test
	public void testSamples() {
		for (String key : samples.keySet()) {
			Set<File> includedFiles = JSPIncludeParser.parse(new File(key));
			Set<String> filePaths = new HashSet<>();
			for (File file : includedFiles) {
				filePaths.add(file.getAbsolutePath());
			}
			
			compare(filePaths, samples.get(key));
		}
	}
	
	@Test
	public void testFakeFile() {
		assertTrue("failure.", JSPIncludeParser.parse(new File(TestConstants.FAKE_FILE)).isEmpty());
	}

	private void compare(@NotNull Set<String> results, @NotNull Set<String> expected) {
		Set<String> resultsCopy = new HashSet<>(results);
		Set<String> expectedCopy = new HashSet<>(expected);
		
		resultsCopy.removeAll(expected);
		expectedCopy.removeAll(results);

		assertTrue("There were more results than expected: " + resultsCopy, resultsCopy.isEmpty());
		assertTrue("The results were missing some entries: " + expectedCopy, expectedCopy.isEmpty());
	}
}
