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
package com.denimgroup.threadfix.framework.impl.spring.auth;

import com.denimgroup.threadfix.framework.ResourceManager;
import com.denimgroup.threadfix.framework.impl.spring.SpringControllerEndpoint;
import com.denimgroup.threadfix.framework.impl.spring.SpringControllerEndpointParser;
import org.junit.Test;

import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mcollins on 3/31/15.
 */
public class EndpointPermissionParsingTests {

    @Test
    public void testClassAuthParsing() {
        Set<SpringControllerEndpoint> endpoints = SpringControllerEndpointParser.parse(
                ResourceManager.getSpringFile("ControllerWithClassAuthorization.java"), null);

        boolean hasAuth = false, hasNoAuth = false;

        for (SpringControllerEndpoint endpoint : endpoints) {
            if (endpoint.getUrlPath().equals("/noAuth")) {
                assert endpoint.getRequiredPermissions().contains("CLASS_ROLE") :
                        "Didn't have CLASS_ROLE: " + endpoint.getRequiredPermissions();
                assert endpoint.getRequiredPermissions().size() == 1 :
                        "Expected size 1: " + endpoint.getRequiredPermissions();
                hasNoAuth = true;
            } else if (endpoint.getUrlPath().equals("/withAuth")) {
                assert endpoint.getRequiredPermissions().containsAll(list("CLASS_ROLE", "METHOD_ROLE")) :
                        "Didn't have all the required permissions: " + endpoint.getRequiredPermissions();
                hasAuth = true;
            }
        }

        assert hasAuth : "Didn't find authenticated endpoint";
        assert hasNoAuth : "Didn't find non-authenticated endpoint";
    }

    @Test
    public void testHasAny() {
        Set<SpringControllerEndpoint> endpoints = SpringControllerEndpointParser.parse(
                ResourceManager.getSpringFile("ControllerWithClassAuthorization.java"), null);

        boolean hasAuth = false, hasNoAuth = false;

        for (SpringControllerEndpoint endpoint : endpoints) {
            if (endpoint.getUrlPath().equals("/noAuth")) {
                assert endpoint.getRequiredPermissions().contains("CLASS_ROLE") :
                        "Didn't have CLASS_ROLE: " + endpoint.getRequiredPermissions();
                assert endpoint.getRequiredPermissions().size() == 1 :
                        "Expected size 1: " + endpoint.getRequiredPermissions();
                hasNoAuth = true;
            } else if (endpoint.getUrlPath().equals("/withAuth")) {
                assert endpoint.getRequiredPermissions().containsAll(list("CLASS_ROLE", "METHOD_ROLE")) :
                        "Didn't have all the required permissions: " + endpoint.getRequiredPermissions();
                hasAuth = true;
            }
        }

        assert hasAuth : "Didn't find authenticated endpoint";
        assert hasNoAuth : "Didn't find non-authenticated endpoint";
    }



}
