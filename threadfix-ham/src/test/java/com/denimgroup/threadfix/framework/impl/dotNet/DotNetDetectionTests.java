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

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import org.junit.Test;

/**
 * Created by mac on 6/17/14.
 */
public class DotNetDetectionTests {

    String[] projects = { "%5bCCS LABS%5d ASP.NET Get Page Version and Platform Version",
            "ASP.NET AJAX web chat application",
            "ASP.NET CMS Administration Template User Administration",
            "ASP.NET MVC 5 – Demo Authentication App with Facebook and Google",
            "ASP.NET MVC Application Using Entity Framework Code First",
            "ASP.NET MVC DataView sample (CSASPNETMVCDataView)",
            "ASP.NET Web Forms Application Using Entity Framework 4.0 Database First",
            "Add new DropDownList option",
            "Architecting Web application using ASP.NET MVC5%2c Web API2 and Knockoutjs",
            "Asp.net Web API CRUD Operations using HTML5 and JQuery",
            "Auto user login in ASP.NET site w HttpWebRequest (CSASPNETAutoLogin)",
            "Background worker thread in ASP.NET (CSASPNETBackgroundWorker)",
            "CRUD Grid Using AngularJS%2c WebAPI%2c Entity Framework (EF)%2c Bootstrap",
            "Chat Web Application in Real Time using ASP.Net MVC and SignalR",
            "Creating Single Page Application using Hot Towel Template",
            "Design Patterns - MVVM - Model View ViewModel Pattern-Part 1",
            "How to construct data to json string before posting to pagemethod using jQuery",
            "How to create a site with AJAX enabled in MVC framework.",
            "Implement Search Engine in ASP.NET Web Site",
            "Insert Update and Delete rows in ASP.NET GridView Control",
            "MVC 4 %2b Knockout CRUD Operations",
            "Magazine management website - An ASP.NET MVC 4 Sample",
            "PDF Editor to Edit PDF Files in your ASP.NET Applications",
            "RESTful API using Web API - Tutorial",
            "Reverse AJAX technique in ASP.NET" };

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
