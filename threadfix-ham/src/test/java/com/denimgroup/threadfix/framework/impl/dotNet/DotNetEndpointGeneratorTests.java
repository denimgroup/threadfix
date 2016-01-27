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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

/**
 * Created by mac on 6/11/14.
 */
public class DotNetEndpointGeneratorTests {

    @Test
    public void testBasicEndpointGenerator() {
        DotNetRouteMappings routeMappings =
                DotNetRoutesParser.parse(ResourceManager.getDotNetMvcFile("RouteConfig.cs"));
        DotNetControllerMappings controllerMappings =
                DotNetControllerParser.parse(ResourceManager.getDotNetMvcFile("ChatController.cs"));

        DotNetEndpointGenerator generator = new DotNetEndpointGenerator(routeMappings, null, controllerMappings);

        assert generator.generateEndpoints().size() == 1 : "Size should have been 1 but was " +
                generator.generateEndpoints().size();

        Endpoint endpoint = generator.generateEndpoints().get(0);

        assert endpoint.getParameters().isEmpty() :
            "Parameters weren't empty. Got " + endpoint.getParameters();
        assert endpoint.getFilePath().endsWith("ChatController.cs") :
            "File path was " + endpoint.getFilePath() + " but should have ended with ChatController.cs";
        assert endpoint.getUrlPath().equals("/Chat") :
            "Actual path was " + endpoint.getUrlPath() + " when it should have been \"/Chat\"";
        assert endpoint.getStartingLineNumber() == 13 :
            "Starting line number was " + endpoint.getStartingLineNumber() + " but should have been 13.";

    }


}
