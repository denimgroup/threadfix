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
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import org.junit.Test;

import java.io.File;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 6/25/14.
 */
public class DotNetEndpointDatabaseTests {

    @Test
    public void testDotNetProjects() {

        List<String> errorMessages = list();

        for (String project : DotNetDetectionTests.projects) {

            System.out.println(project);

            EndpointDatabase database = EndpointDatabaseFactory.getDatabase(new File(TestConstants.DOT_NET_ROOT + "/" + project));

            if (database == null) {
                errorMessages.add("Database was null for project " + project);
            } else if (database.getFrameworkType() != FrameworkType.DOT_NET_MVC) {
                errorMessages.add("Got " + database.getFrameworkType() + " instead of DOT_NET for " + project);
            } else if (database.generateEndpoints().size() == 0) {
                errorMessages.add("Database was empty for "  + project);
            }
        }

        if (!errorMessages.isEmpty()) {
            for (String message : errorMessages) {
                System.out.println(message);
            }

            assert false : "See errors above.";
        }
    }
}
