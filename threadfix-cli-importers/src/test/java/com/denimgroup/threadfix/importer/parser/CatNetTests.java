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

public class CatNetTests extends TransactionalTest {

    public final static String[][] catnetResults = {
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\ContactUs.aspx", "email"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\ContactUs.aspx", "txtMessage"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\ContactUs.aspx", "txtSubject"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\MakePayment.aspx", "txtAmount"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\MakePayment.aspx", "txtAmount"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\MakePayment.aspx", "txtCardNumber"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\Message.aspx", "Msg"},
            { SQLI, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\LoginPage.aspx", "txtPassword"},
            { SQLI, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\LoginPage.aspx", "txtUsername"},
            { SQLI, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\MakePayment.aspx", "txtAmount"},
            { SQLI, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\ViewStatement.aspx", "StatementID"},
    };

    @Test
    public void catNetTests() {
        ScanComparisonUtils.compare(catnetResults, ScanLocationManager.getRoot() +
                "Static/CAT.NET/catnet_RiskE.xml");
    }

}