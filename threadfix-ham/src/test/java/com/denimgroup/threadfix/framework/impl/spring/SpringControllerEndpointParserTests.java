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

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.ResourceManager;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.util.java.EntityMappings;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SpringControllerEndpointParserTests {

    @Nonnull
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
    public void testClassRequestParamAnnotation() {
        EntityMappings mappings = new EntityMappings(new File(TestConstants.PETCLINIC_SOURCE_LOCATION));

        File file = ResourceManager.getSpringFile(TestConstants.SPRING_CONTROLLER_WITH_CLASS_REQUEST_MAPPING);

        Set<? extends Endpoint> endpoints =
                SpringControllerEndpointParser.parse(file, mappings);

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

    @Test
    public void testMathController() {
        Set<SpringControllerEndpoint> endpoints = parseEndpoints("MathController.java", "mvc-calculator");
        assertTrue("Size was " + endpoints.size() + " instead of 1.", endpoints.size() == 1);
    }

    @Test
    public void testCityController() {
        Set<SpringControllerEndpoint> endpoints = parseEndpoints("CityController.java", "mvc-calculator");
        assertTrue("Size was " + endpoints.size() + " instead of 6.", endpoints.size() == 6);
    }

    @Test
    public void testAllFrameworks() {
        for (String app : SpringDetectionTests.ALL_SPRING_APPS) {
            EndpointGenerator mappings = new SpringControllerMappings(new File(TestConstants.getFolderName(app)));
            assertFalse("No endpoints found in app " + app + ".", mappings.generateEndpoints().isEmpty());
        }
    }

    @Test
    public void testModelBindingRecognition() {
        for (Endpoint endpoint : parseEndpoints("ProjectsController.java", "ticketline-spring")) {
            assertTrue("Couldn't find name in " + endpoint.getUrlPath(), endpoint.getParameters().contains("name"));
            assertTrue("Couldn't find description in " + endpoint.getUrlPath(), endpoint.getParameters().contains("description"));
        }
    }

    @Test
    public void testRequestParamParsing() {
        for (Endpoint endpoint : parseEndpoints("ParamsController.java", "mvc-calculator")) {
            assertTrue("Found no parameters for method " + endpoint.getUrlPath(), endpoint.getParameters().size() > 0);
            assertTrue("Endpoint param was " + endpoint.getParameters().iterator().next() +
                    " instead of integer for method " + endpoint.getUrlPath(),
                    endpoint.getParameters().iterator().next().equals("integer"));
        }
    }

    @Test
    public void testMethodAuthParsing() {
        Set<SpringControllerEndpoint> endpoints = SpringControllerEndpointParser.parse(
                ResourceManager.getSpringFile("ControllerWithAuthentication.java"), null);

        boolean hasAuth = false, hasNoAuth = false;

        for (SpringControllerEndpoint endpoint : endpoints) {
            if (endpoint.getUrlPath().equals("/noAuth")) {
                assert endpoint.getAuthorizationString() == null :
                    "Expected null, but got " + endpoint.getAuthorizationString();
                hasNoAuth = true;
            } else if (endpoint.getUrlPath().equals("/withAuth")) {
                assert endpoint.getAuthorizationString().equals("hasRole('ROLE')") :
                    "Expected hasRole('ROLE') but got " + endpoint.getAuthorizationString();
                hasAuth = true;
            }
        }

        assert hasAuth : "Didn't find authenticated endpoint";
        assert hasNoAuth : "Didn't find non-authenticated endpoint";
    }

    @Test
    public void testClassAuthParsing() {
        Set<SpringControllerEndpoint> endpoints = SpringControllerEndpointParser.parse(
                ResourceManager.getSpringFile("ControllerWithClassAuthorization.java"), null);

        boolean hasAuth = false, hasNoAuth = false;

        for (SpringControllerEndpoint endpoint : endpoints) {
            if (endpoint.getUrlPath().equals("/noAuth")) {
                assert endpoint.getAuthorizationString().equals("hasRole('CLASS_ROLE')") :
                    "Expected hasRole('CLASS_ROLE'), but got " + endpoint.getAuthorizationString();
                hasNoAuth = true;
            } else if (endpoint.getUrlPath().equals("/withAuth")) {
                assert endpoint.getAuthorizationString().equals("hasRole('CLASS_ROLE') and hasRole('METHOD_ROLE')") :
                    "Expected hasRole('CLASS_ROLE') and hasRole('METHOD_ROLE') but got " + endpoint.getAuthorizationString();
                hasAuth = true;
            }
        }

        assert hasAuth : "Didn't find authenticated endpoint";
        assert hasNoAuth : "Didn't find non-authenticated endpoint";
    }

    Set<SpringControllerEndpoint> parseEndpoints(String controllerName, String rootFolderName) {
        return SpringControllerEndpointParser.parse(ResourceManager.getSpringFile(controllerName),
                new EntityMappings(new File(TestConstants.getFolderName(rootFolderName))));
    }


}
