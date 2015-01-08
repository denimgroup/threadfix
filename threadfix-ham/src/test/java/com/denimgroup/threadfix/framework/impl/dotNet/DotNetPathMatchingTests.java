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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.ResourceManager;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import org.junit.Test;

import java.util.Set;

public class DotNetPathMatchingTests {

    public static DotNetRouteMappings routeMappings =
            DotNetRoutesParser.parse(ResourceManager.getDotNetMvcFile("InstructorRoutes.cs"));

    @Test
    public void testPathMatchingWithParameter() {

        DotNetControllerMappings mappings =
                DotNetControllerParser.parse(ResourceManager.getDotNetMvcFile("InstructorController.cs"));

        DotNetEndpointGenerator generator =
                new DotNetEndpointGenerator(routeMappings, null, mappings);

        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(
                generator, FrameworkType.DOT_NET_MVC, new DotNetPathCleaner());

        assert database != null;

        EndpointQuery query = EndpointQueryBuilder.start().setDynamicPath("/Instructor/Details/6").generateQuery();

        Set<Endpoint> allMatches = database.findAllMatches(query);

        assert allMatches.size() == 1 : "Size was " + allMatches.size() + " instead of 1.";

    }


}
