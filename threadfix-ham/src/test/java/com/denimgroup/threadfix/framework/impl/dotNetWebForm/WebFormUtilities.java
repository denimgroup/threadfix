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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.framework.engine.ThreadFixInterface;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;

import java.io.File;

/**
 * Created by mac on 9/5/14.
 */
public class WebFormUtilities {

    public static EndpointDatabase getWebFormDatabase(Scan inputScan) {
        return EndpointDatabaseFactory.getDatabase(
                getWebFormLocation(),
                ThreadFixInterface.toPartialMappingList(inputScan)
        );
    }

    public static File getWebFormLocation() {
        String root = System.getProperty("PROJECTS_ROOT");
        assert root != null && new File(root).exists() : "Projects root didn't exist or was invalid.";

        String total = root + "ASP.NET/Add new DropDownList option";

        assert new File(total).exists() : "WebForms project didn't exist at " + total;

        System.out.println("Getting database from " + total);

        return new File(total);
    }
}
