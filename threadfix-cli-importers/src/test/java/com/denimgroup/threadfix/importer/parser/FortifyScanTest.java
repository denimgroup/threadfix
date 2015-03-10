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

package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class FortifyScanTest extends TransactionalTest {

    public final static String[][] fortify360Results = new String [][] {
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "Address"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "BillingDate"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "BillingDate"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "CcfUsed"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "CityServices"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "CurrentElectricity"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "CurrentNaturalGas"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "CustomerNumber"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "CustomerNumber"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "KiloWattHourUsed"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "Name"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "Payments"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "PreviousBill"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", "StateLocalTaxes"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ContactUs.aspx.cs", "email"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ContactUs.aspx.cs", "txtSubject"},
            {XSS, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/MakePayment.aspx.cs", "txtCardNumber"},
            {XSS, "High", "my documents/visual studio 2008/projects/riske/riske/zigguratutilityweb/message.aspx", "Msg"},
            {SQLI, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/LoginPage.aspx.cs", "txtUsername"},
            {SQLI, "High", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/App_Code/DBUtil.cs", "StatementID"},
            {ASP_NET_DEBUG, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/web.config", ""},
            {ASP_NET_CUSTOM_ERROR, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/web.config", ""},
            {ASP_NET_VALIDATION_MISSING, "Medium", "my documents/visual studio 2008/projects/riske/riske/zigguratutilityweb/message.aspx", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/Home.aspx.cs", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/Home.aspx.cs", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/LoginPage.aspx.cs", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/ViewStatement.aspx.cs", ""},
            {NON_SERIALIZABLE_OBJECT, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/LoginPage.aspx.cs", ""},
            {TRUST_BOUNDARY_VIOLATION, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/LoginPage.aspx.cs", ""},
            {NULL_POINTER, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/Home.aspx.cs", ""},
            {NULL_POINTER, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/MakePayment.aspx.cs", ""},
            {NULL_POINTER, "Medium", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/MakePayment.aspx.cs", ""},
            {SQLI, "Info", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/App_Code/DBUtil.cs", ""},
            {UNCHECKED_ERROR, "Info", "My Documents/Visual Studio 2008/Projects/RiskE/RiskE/ZigguratUtilityWeb/App_Code/DBUtil.cs", ""}
    };

    @Test
    public void fortifyScanTest() {
        ScanComparisonUtils.compare(fortify360Results, ScanLocationManager.getRoot() +
                "Static/Fortify/ZigguratUtility.fpr");
    }

    @Test
    public void fortifyScanTest2() {
        ScanComparisonUtils.compare(new String[][]{}, ScanLocationManager.getRoot() +
                "Static/Fortify/Webgoat-full.fpr");
    }
}
