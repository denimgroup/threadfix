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
package com.denimgroup.threadfix.framework.impl.jsp;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;
import static com.denimgroup.threadfix.CollectionUtils.setFrom;
import static org.junit.Assert.assertTrue;

// TODO add more tests
public class JSPIncludeParserTests {

	@Test
	public void testPercentArrobaFormat() {
        String file = TestConstants.WAVSEP_SOURCE_LOCATION + "/trunk/WebContent/active/LFI-Detection-Evaluation-GET-404Error/Case49-LFI-ContextStream-FilenameContext-UnixTraversalValidation-OSPath-DefaultFullInput-SlashPathReq-Read.jsp";

        String[] files = {
                TestConstants.WAVSEP_SOURCE_LOCATION + "/trunk/WebContent/active/LFI-Detection-Evaluation-GET-404Error/inclusion-logic.jsp",
                TestConstants.WAVSEP_SOURCE_LOCATION + "/trunk/WebContent/active/LFI-Detection-Evaluation-GET-404Error/include.jsp"
        };

        Set<File> includedFiles = JSPIncludeParser.parse(new File(file));

        compare(includedFiles, Arrays.asList(files));
	}

    @Test
    public void testJspIncludeFormat() {
        String file = TestConstants.BODGEIT_SOURCE_LOCATION + "/root/basket.jsp";

        String[] files = {
                TestConstants.BODGEIT_SOURCE_LOCATION + "/root/header.jsp",
                TestConstants.BODGEIT_SOURCE_LOCATION + "/root/footer.jsp",
        };

        Set<File> includedFiles = JSPIncludeParser.parse(new File(file));

        compare(includedFiles, Arrays.asList(files));
    }

    // Since header.jsp is in every page, the debug parameter should also be in every page.
    @Test
    public void testParameters() {
        EndpointGenerator generator = new JSPMappings(new File(TestConstants.BODGEIT_SOURCE_LOCATION));

        for (Endpoint endpoint : generator) {

            // footer.jsp and init.jsp don't have debug, but all the others should.
            if (!endpoint.getFilePath().equals("/root/footer.jsp") && !endpoint.getFilePath().equals("/root/init.jsp"))
                assertTrue("Endpoint " + endpoint.getFilePath() + " didn't have the debug parameter",
                    endpoint.getParameters().contains("debug"));
        }
    }
	
	@Test
	public void testFakeFile() {
		assertTrue("failure.", JSPIncludeParser.parse(new File(TestConstants.FAKE_FILE)).isEmpty());
	}

	private void compare(@Nonnull Collection<File> results, @Nonnull Collection<String> expected) {
		Set<String> resultsCopy = set();
		Set<String> expectedCopy = setFrom(expected);

        for (File file : results) {
            resultsCopy.add(file.getAbsolutePath());
        }
		
		expectedCopy.removeAll(resultsCopy);
        resultsCopy.removeAll(expected);

		assertTrue("There were more results than expected: " + resultsCopy, resultsCopy.isEmpty());
		assertTrue("The results were missing some entries: " + expectedCopy, expectedCopy.isEmpty());
	}
}
