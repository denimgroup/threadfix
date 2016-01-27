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

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import org.junit.Test;

/**
 * Created by mac on 6/17/14.
 */
public class DotNetDetectionTests {

    static String[] projects = {
            "ASP.NET MVC 5 Demo Authentication App with Facebook and Google",
            "ASP.NET MVC Application Using Entity Framework Code First",
            "ASP.NET MVC DataView sample (CSASPNETMVCDataView)",
            "Architecting Web application using ASP.NET MVC5%2c Web API2 and Knockoutjs",
            "CRUD Grid Using AngularJS%2c WebAPI%2c Entity Framework (EF)%2c Bootstrap",
            "Chat Web Application in Real Time using ASP.Net MVC and SignalR",
            "Creating Single Page Application using Hot Towel Template",
            "How to create a site with AJAX enabled in MVC framework",
            "MVC 4 %2b Knockout CRUD Operations",
            "Magazine management website - An ASP.NET MVC 4 Sample",
            "RESTful API using Web API - Tutorial",
    };

    @Test
    public void testDotNetProjects() {
        for (String project : projects) {

            System.out.println(project);

            FrameworkType type = FrameworkCalculator.getType(TestConstants.DOT_NET_ROOT + "/" + project);

            assert type == FrameworkType.DOT_NET_MVC
                    : "Got " + type + " instead of DOT_NET for " + project;
        }
    }
}
