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

import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 6/11/14.
 */
public class DotNetRouteMappings {

    static class ConcreteRoute {
        ConcreteRoute(String controller, String action, String parameter) {
            assert action != null;
            assert controller != null;
            this.action = action;
            this.parameter = parameter;
            this.controller = controller;
        }

        String parameter;
        String action;
        String controller;
    }

    static class MapRoute {
        String        name;
        String        url;
        ConcreteRoute defaultRoute;

        MapRoute(String name, String url, ConcreteRoute defaultRoute) {
            assert name != null;
            assert url != null;
            this.name = name;
            this.url = url;
            this.defaultRoute = defaultRoute;
        }
    }

    public boolean hasDefaultParam(Set<String> parameters) {
        assert !routes.isEmpty() : "Attempting to access data from empty DotNetRouteMappings";
        if (routes.size() > 1) {
            throw new IllegalStateException("Throwing an exception for now until we figure out what to do in this case");
        }

        return parameters.contains(routes.get(0).defaultRoute.parameter);
    }

    List<MapRoute> routes = list();

    public DotNetRouteMappings() {}

    public void addRoute(String name, String url, String controller, String action, String parameter) {
        ConcreteRoute defaultRoute = controller != null && action != null ?
                new ConcreteRoute(controller, action, parameter) :
                null;
        routes.add(new MapRoute(name, url, defaultRoute));
    }

}
