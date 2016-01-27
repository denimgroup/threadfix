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
package com.denimgroup.threadfix.framework.impl.rails.model;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by sgerick on 5/5/2015.
 */
public class RailsRoute {
    private String url;
    private List<String> httpMethods;
    //private String controller;

    public RailsRoute() {
    }

    public RailsRoute(String url, String method) {
        this.setUrl(url);
        this.addHttpMethod(method);
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public List<String> getHttpMethods() {
        return httpMethods;
    }

    public void addHttpMethod(String method) {
        if (this.httpMethods == null)
            this.httpMethods = list();
        if (!httpMethods.contains(method)) {
            this.httpMethods.add(method);
        }
    }

//    public String getController() {
//        return controller;
//    }
//
//    public void setController(String controller) {
//        this.controller = controller;
//    }

}
