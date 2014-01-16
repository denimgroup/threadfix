package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.ResourceManager;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.TestUtils;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.util.*;

import static junit.framework.Assert.assertTrue;

// TODO add more tests?
public class SpringDataBinderTests {

    File editAppController = ResourceManager.getSpringFile("databinder/EditApplicationController.java");

    Set<String> defaultParameters = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("name", "url", "defectTracker.id", "userName",
            "password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id",
            "uniqueId", "organization.id", "frameworkType", "repositoryUrl", "repositoryFolder")));

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
        SpringEntityMappings threadfixMappings =
                new SpringEntityMappings(new File(TestConstants.THREADFIX_SOURCE_ROOT));

        Set<SpringControllerEndpoint> endpointSet =
                SpringControllerEndpointParser.parse(editAppController, threadfixMappings);

        Set<String> acceptableParameters = new HashSet<>(Arrays.asList("name", "url", "defectTracker.id", "userName",
                "password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id", "orgId", "appId",
                "uniqueId", "organization.id", "frameworkType", "repositoryUrl", "repositoryFolder"));

        for (SpringControllerEndpoint endpoint : endpointSet) {
            for (String parameter : endpoint.getParameters()) {
                assertTrue(parameter + " wasn't included in set. Endpoint: " + endpoint,
                        acceptableParameters.contains(parameter));
            }
            assertTrue(endpoint.getParameters().contains("appId"));
            assertTrue(endpoint.getParameters().contains("orgId"));
        }
    }
}
