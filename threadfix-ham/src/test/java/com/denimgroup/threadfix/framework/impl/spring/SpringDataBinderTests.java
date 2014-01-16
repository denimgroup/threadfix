package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.ResourceManager;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static junit.framework.Assert.assertTrue;

/**
 * Created by mcollins on 1/15/14.
 */
public class SpringDataBinderTests {

    File editAppController = ResourceManager.getSpringFile("EditApplicationController.java");

    @Test
    public void testSimple() {
        SpringDataBinderParser parser = new SpringDataBinderParser();
        EventBasedTokenizerRunner.run(editAppController, parser);

        assertTrue("Parser didn't have whitelist", parser.hasWhitelist);

        Set<String> acceptableParameters = new HashSet<>(Arrays.asList("name", "url", "defectTracker.id", "userName",
                "password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id",
                "uniqueId", "organization.id", "frameworkType", "repositoryUrl", "repositoryFolder"));

        Set<String> paramsCopy = new HashSet<>(parser.parametersWhiteList),
            expectedCopy = new HashSet<>(acceptableParameters);

        paramsCopy.removeAll(acceptableParameters);
        expectedCopy.removeAll(parser.parametersWhiteList);

        assertTrue("Parsed parameters has extra params " + expectedCopy, expectedCopy.size() == 0);
        assertTrue("Parsed parameters were missing " + paramsCopy, paramsCopy.size() == 0);
    }

    @Ignore
    @Test
    public void testIntegrated() {
        SpringEntityMappings threadfixMappings = new SpringEntityMappings(new File(TestConstants.THREADFIX_SOURCE_ROOT));

        Set<SpringControllerEndpoint> endpointSet = SpringControllerEndpointParser.parse(editAppController, threadfixMappings);

        Set<String> acceptableParameters = new HashSet<>(Arrays.asList("name", "url", "defectTracker.id", "userName",
                "password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id", "orgId", "appId",
                "uniqueId", "organization.id", "frameworkType", "repositoryUrl", "repositoryFolder"));

        for (SpringControllerEndpoint endpoint : endpointSet) {
            for (String parameter : endpoint.getParameters()) {
                assertTrue(parameter + " wasn't included in set. Endpoint: " + endpoint, acceptableParameters.contains(parameter));
            }
        }
    }

}
