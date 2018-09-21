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

import com.denimgroup.threadfix.framework.ResourceManager;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.TestUtils;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import com.denimgroup.threadfix.framework.util.java.EntityMappings;
import org.junit.Test;

import java.io.File;
import java.util.Collections;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;
import static org.junit.Assert.assertTrue;

// TODO add more tests?
public class SpringDataBinderTests {

    File editAppController = ResourceManager.getSpringFile("databinder/EditApplicationController2.java");

    Set<String> defaultParameters = Collections.unmodifiableSet(set("name", "url", "defectTracker.id", "userName",
            "password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id",
            "uniqueId", "organization.id", "frameworkType", "repositoryUrl", "repositoryFolder"));

    private SpringDataBinderParser getParser(File file) {
        SpringDataBinderParser parser = new SpringDataBinderParser();
        EventBasedTokenizerRunner.run(file, parser);
        return parser;
    }

    @Test
    public void testSetAllowedFields() {
        SpringDataBinderParser parser = getParser(editAppController);
        assertTrue("Parser didn't have whitelist", parser.hasWhitelist);
        TestUtils.compare(parser.parametersWhiteList, defaultParameters, "Parsed parameters");
    }

    @Test
    public void testSetDisallowedFields() {
        SpringDataBinderParser parser = getParser(ResourceManager.getSpringFile("databinder/BasicDisallowedFields.java"));
        assertTrue("Parser didn't have blacklist", parser.hasBlacklist);
        TestUtils.compare(parser.parametersBlackList, defaultParameters, "Parsed parameters");
    }

    @Test
    public void testBothSameMethod() {
        SpringDataBinderParser parser = getParser(ResourceManager.getSpringFile("databinder/BlackAndWhiteLists.java"));
        assertTrue("Parser didn't have whitelist", parser.hasWhitelist);
        assertTrue("Parser didn't have blacklist", parser.hasBlacklist);
        TestUtils.compare(parser.parametersWhiteList, defaultParameters, "Parsed parameters");
        TestUtils.compare(parser.parametersBlackList, defaultParameters, "Parsed parameters");
    }

    @Test
    public void testBothDifferentMethods() {
        SpringDataBinderParser parser = getParser(ResourceManager.getSpringFile("databinder/BothInDifferentMethods.java"));
        assertTrue("Parser didn't have whitelist", parser.hasWhitelist);
        assertTrue("Parser didn't have blacklist", parser.hasBlacklist);
        TestUtils.compare(parser.parametersWhiteList, defaultParameters, "Parsed parameters");
        TestUtils.compare(parser.parametersBlackList, defaultParameters, "Parsed parameters");
    }

    @Test
    public void testIntegration() {
        if (!new File(TestConstants.THREADFIX_SOURCE_ROOT).exists()) {
            throw new IllegalStateException("The ThreadFix source folder was not found at " +
                    TestConstants.THREADFIX_SOURCE_ROOT);
        }

        EntityMappings threadfixMappings =
                new EntityMappings(new File(TestConstants.THREADFIX_SOURCE_ROOT));

        Set<SpringControllerEndpoint> endpointSet =
                SpringControllerEndpointParser.parse(editAppController, threadfixMappings);

        // we have to initialize the databinder and add to the endpoints
        SpringDataBinderParser dataBinderParser = new SpringDataBinderParser();
        EventBasedTokenizerRunner.run(editAppController, dataBinderParser);

        Set<String> acceptableParameters = set("name", "url", "defectTracker.id", "userName",
                "password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id", "orgId", "appId",
                "uniqueId", "organization.id", "frameworkType", "repositoryUrl", "repositoryFolder");

        for (SpringControllerEndpoint endpoint : endpointSet) {

            endpoint.setDataBinderParser(dataBinderParser);
            endpoint.expandParameters(threadfixMappings, null);

            for (String parameter : endpoint.getParameters()) {
                assertTrue(parameter + " wasn't included in set. Endpoint: " + endpoint,
                        acceptableParameters.contains(parameter));
            }
            assertTrue("Parameters didn't include appId", endpoint.getParameters().contains("appId"));
            assertTrue("Parameters didn't include orgId", endpoint.getParameters().contains("orgId"));
        }
    }
}
