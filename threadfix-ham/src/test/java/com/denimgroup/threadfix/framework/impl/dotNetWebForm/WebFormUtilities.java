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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.ThreadFixInterface;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

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

    @Nonnull
    public static File getWebFormLocation() {
        String root = System.getProperty("PROJECTS_ROOT");
        assert root != null && new File(root).exists() : "Projects root didn't exist or was invalid.";

        String total = root + "ASP.NET/Add new DropDownList option";

        assert new File(total).exists() : "WebForms project didn't exist at " + total;

        System.out.println("Getting database from " + total);

        return new File(total);
    }

    @Nonnull
    public static List<File> getSampleProjects() {
        File rootFile = new File(TestConstants.WEB_FORMS_ROOT);

        assert rootFile.exists() : "File at " + TestConstants.WEB_FORMS_ROOT + " was invalid.";

        assert rootFile.isDirectory() : TestConstants.WEB_FORMS_ROOT + " wasn't a directory.";

        File[] files = rootFile.listFiles();

        assert files != null : "Files returned from listFiles() were null.";

        List<File> returnList = list();

        for (File file : files) {
            if (!file.getName().startsWith(".") && !file.isFile()) {
                returnList.add(file);
            }
        }

        return returnList;
    }
}
