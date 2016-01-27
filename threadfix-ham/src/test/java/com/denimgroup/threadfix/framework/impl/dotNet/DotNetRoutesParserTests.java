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

import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

public class DotNetRoutesParserTests {

    @Test
    public void testBasicRouteConfig() {
        testFile("RouteConfig.cs", "Chat", "Index");
    }

    @Test
    public void testGlobalAsaxFile() {
        testFile("Global.asax.cs", "Ajax", "JQueryHelper");
    }

    public void testFile(String fileExtension, String controller, String action) {
        DotNetRouteMappings mappings =
                DotNetRoutesParser.parse(ResourceManager.getDotNetMvcFile(fileExtension));

        assert mappings.routes.size() == 1 : mappings.routes.size() + " routes were found, but 1 was expected.";

        DotNetRouteMappings.MapRoute route = mappings.routes.get(0);

        assert route.name.equals("Default") :
                "Name should have been default but it was " + route.name;
        assert route.url.equals("{controller}/{action}/{id}") :
                "URL should have been {controller}/{action}/{id} but was " + route.url;
        assert route.defaultRoute != null :
                "Default route was null.";
        assert route.defaultRoute.controller.equals(controller) :
                "Was expecting Chat but got " + route.defaultRoute.controller;
        assert route.defaultRoute.action.equals(action) :
                "Was expecting Index but got " + route.defaultRoute.action;
    }
}
