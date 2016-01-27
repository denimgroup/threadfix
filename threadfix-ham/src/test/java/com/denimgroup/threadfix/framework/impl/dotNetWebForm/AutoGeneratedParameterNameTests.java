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

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Set;

/**
 * Created by mac on 10/20/14.
 */
public class AutoGeneratedParameterNameTests {

    @Test
    public void testContosoGeneratedProperties() {
        String[] params = {
                "ctl00$MainContent$StudentsDetailsView$ctl01",
                "ctl00$MainContent$StudentsDetailsView$ctl02",
                "ctl00$MainContent$StudentsDetailsView$ctl03"
        };

        checkParameters(TestConstants.WEB_FORMS_CONTOSO, "/StudentsAdd.aspx", params);
    }

    @Test
    public void testFullIntegration() {
        String[] params = {
                "ctl00$masterpage$ctl01",
                "ctl00$masterpage$ctl02",
                "ctl00$masterpage$ctl03",
                "ctl00$masterpage$ctl04",
                "ctl00$MainContent$ctl00$ctl01",
                "ctl00$MainContent$ctl00$ctl02",
                "ctl00$MainContent$ctl00$ctl03",
                "ctl00$MainContent$ctl00$ctl04",
                "ctl00$MainContent$WebUserControl1$textColor",
                "ctl00$MainContent$WebUserControl1$DetailsView1$ctl01",
                "ctl00$MainContent$WebUserControl1$DetailsView1$ctl02",
                "ctl00$MainContent$WebUserControl1$DetailsView1$ctl03",
                "ctl00$MainContent$WebUserControl1$DetailsView1$ctl04"
        };

        checkParameters(TestConstants.WEB_FORMS_MODIFIED, "/StudentsAdd.aspx", params);
    }

    @Test
    public void testRiskEParameters() {
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(TestConstants.RISK_E_UTILITY);

        checkParameters(database, "/ViewStatement.aspx", "StatementID");
        checkParameters(database, "/LoginPage.aspx", "txtPassword", "txtUsername");
        checkParameters(database, "/Message.aspx", "Msg");
        checkParameters(database, "/MakePayment.aspx", "txtCardNumber");
    }

    @Test
    @Ignore // this works locally but breaks in our CI
    public void testWebGoatDotNetParameters() {
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(TestConstants.WEBGOAT_DOT_NET);

        checkParameters(database, "/WebGoatCoins/ChangePassword.aspx", "txtPassword1", "txtPassword2");
        checkParameters(database, "/WebGoatCoins/CustomerLogin.aspx", "txtUserName", "txtPassword");
        checkParameters(database, "/WebGoatCoins/ForgotPassword.aspx", "txtAnswer", "txtEmail");
        checkParameters(database, "/WebGoatCoins/ProductDetails.aspx", "productNumber", "txtEmail", "txtComment", "hiddenFieldProductID");
        checkParameters(database, "/AddNewUser.aspx", "Username", "Password", "Email", "SecurityAnswer");
        checkParameters(database, "/ProxySetup.aspx", "txtName");
    }

    private void checkParameters(String databaseLocation, String endpointUrl, String... params) {
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(databaseLocation);

        assert database != null : "Database was null for " + databaseLocation;

        checkParameters(database, endpointUrl, params);
    }

    // having this separate enables us to reuse a database between test calls to save parsing time
    private void checkParameters(EndpointDatabase database, String endpointUrl, String... params) {
        EndpointQuery query =
                EndpointQueryBuilder
                        .start()
                        .setDynamicPath(endpointUrl)
                        .generateQuery();

        Set<Endpoint> allMatches = database.findAllMatches(query);

        assert allMatches.size() == 1 :
                "Got " + allMatches.size() + " endpoints for " + endpointUrl + ": " + allMatches;

        Endpoint endpoint = allMatches.iterator().next();

        for (String param : params) {
            assert endpoint.getParameters().contains(param) :
                    "Parameters for " + endpointUrl + " didn't contain " + param + " : " + endpoint.getParameters();
        }
    }
}
