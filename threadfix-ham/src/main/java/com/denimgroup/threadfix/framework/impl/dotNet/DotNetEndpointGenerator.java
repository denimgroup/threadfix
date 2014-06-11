////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;

import javax.annotation.Nonnull;
import java.util.*;

/**
 * Created by mac on 6/11/14.
 */
public class DotNetEndpointGenerator implements EndpointGenerator {

    private final DotNetControllerMappings[] dotNetControllerMappings;
    private final DotNetRouteMappings        dotNetRouteMappings;
    private final Set<Endpoint> endpoints = new HashSet<>();

    public DotNetEndpointGenerator(DotNetRouteMappings routeMappings, DotNetControllerMappings... controllerMappings) {
        assert routeMappings != null;
        assert controllerMappings != null;
        assert controllerMappings.length != 0;

        dotNetControllerMappings = controllerMappings;
        dotNetRouteMappings = routeMappings;

        assembleEndpoints();
    }

    private void assembleEndpoints() {
        DotNetRouteMappings.MapRoute mapRoute = dotNetRouteMappings.routes.get(0);

        for (DotNetControllerMappings mappings : dotNetControllerMappings) {
            for (String action : mappings.getActions()) {
                String pattern = mapRoute.url;

                String result = pattern
                        // substitute in controller name for {controller}
                        .replaceAll("\\{\\w*controller\\w*\\}", mappings.getControllerName())
                        // substitute in action for {action}
                        .replaceAll("\\{\\w*action\\w*\\}", action)
                        // parse out parameters instead of ignoring them.
                        .replaceAll("\\{[^\\}]*\\}", ""); // strip all of the other things

                endpoints.add(
                        new DotNetEndpoint(result, mappings.getFilePath(), mappings.getLineNumberForAction(action)));
            }
        }
    }

    @Nonnull
    @Override
    public List<Endpoint> generateEndpoints() {
        return new ArrayList<>(endpoints);
    }

    @Override
    public Iterator<Endpoint> iterator() {
        return endpoints.iterator();
    }
}
