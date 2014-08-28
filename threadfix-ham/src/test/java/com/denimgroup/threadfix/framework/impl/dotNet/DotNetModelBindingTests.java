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

import com.denimgroup.threadfix.data.enums.InformationSourceType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import org.junit.Test;

import java.io.File;
import java.util.Set;

import static com.denimgroup.threadfix.framework.impl.dotNet.ContosoUtilities.getContosoLocation;

/**
 * Created by mac on 8/26/14.
 */
public class DotNetModelBindingTests {

    @Test
    public void testModelBindingParser() {

    }

    public static final String project = "ASP.NET MVC 5 Demo Authentication App with Facebook and Google",
            folderName = TestConstants.DOT_NET_ROOT + "/" + project;

    @Test
    public void testEndpointDatabase() {
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(new File(folderName));

        assert database != null : "Unable to generate a database for " + folderName + ", check the filesystem.";

        EndpointQuery endpointQuery = EndpointQueryBuilder.start()
                .setHttpMethod("POST")
                .setDynamicPath("/Account/Login")
                .setParameter("UserName")
                .setInformationSourceType(InformationSourceType.DYNAMIC)
                .generateQuery();

        Set<Endpoint> allMatches = database.findAllMatches(endpointQuery);

        assert allMatches.size() == 1 : "No endpoint was found.";

        Set<String> parameters = allMatches.iterator().next().getParameters();

        assert parameters.contains("UserName") :
                "Endpoint didn't have the UserName parameter.";
        assert parameters.contains("Password") :
                "Endpoint didn't have the Password parameter.";
        assert parameters.contains("RememberMe") :
                "Endpoint didn't have the RememberMe parameter.";
    }

    // This test is meant to ensure that the model parameter is not included (student in this case)
    @Test
    public void testBindIncludeParameters() {
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(getContosoLocation());

        assert database != null : "Unable to generate a database for " + folderName + ", check the filesystem.";

        EndpointQuery endpointQuery = EndpointQueryBuilder.start()
                .setHttpMethod("POST")
                .setDynamicPath("/Student/Create")
                .setParameter("LastName")
                .setInformationSourceType(InformationSourceType.DYNAMIC)
                .generateQuery();

        Set<Endpoint> allMatches = database.findAllMatches(endpointQuery);

        assert allMatches.size() == 1 : allMatches.size() + " endpoint(s) found.";

        Set<String> parameters = allMatches.iterator().next().getParameters();

        assert parameters.size() == 3 :
                "Got " + parameters.size() + " parameters instead of 3: " + parameters;
        assert parameters.contains("LastName") :
                "Endpoint didn't have the LastName parameter.";
        assert parameters.contains("FirstMidName") :
                "Endpoint didn't have the FirstMidName parameter.";
        assert parameters.contains("EnrollmentDate") :
                "Endpoint didn't have the EnrollmentDate parameter.";
    }

}
