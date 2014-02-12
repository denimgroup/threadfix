package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class FortifyScanTest {

    public final static String[][] fortify360Results = new String [][] {
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Address"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "BillingDate"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "BillingDate"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CcfUsed"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CityServices"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CurrentElectricity"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CurrentNaturalGas"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CustomerNumber"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "CustomerNumber"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "KiloWattHourUsed"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Name"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "Payments"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "PreviousBill"},
            {XSS, "High", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", "StateLocalTaxes"},
            {XSS, "High", "/ZigguratUtilityWeb/ContactUs.aspx", "email"},
            {XSS, "High", "/ZigguratUtilityWeb/ContactUs.aspx", "txtSubject"},
            {XSS, "High", "/ZigguratUtilityWeb/MakePayment.aspx", "txtCardNumber"},
            {XSS, "High", "/zigguratutilityweb/message.aspx", "Msg"},
            {SQLI, "High", "/ZigguratUtilityWeb/LoginPage.aspx", "txtUsername"},
            {SQLI, "High", "/ZigguratUtilityWeb/ViewStatement.aspx", "StatementID"},
            {ASP_NET_DEBUG, "Medium", "/ZigguratUtilityWeb/web.config", ""},
            {ASP_NET_CUSTOM_ERROR, "Medium", "/ZigguratUtilityWeb/web.config", ""},
            {ASP_NET_VALIDATION_MISSING, "Medium", "/zigguratutilityweb/message.aspx", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/ViewStatement.aspx", ""},
            {IMPROPER_RESOURCE_SHUTDOWN, "Medium", "/ZigguratUtilityWeb/ViewStatement.aspx", ""},
            {NON_SERIALIZABLE_OBJECT, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
            {TRUST_BOUNDARY_VIOLATION, "Medium", "/ZigguratUtilityWeb/LoginPage.aspx", ""},
            {NULL_POINTER, "Medium", "/ZigguratUtilityWeb/Home.aspx", ""},
            {NULL_POINTER, "Medium", "/ZigguratUtilityWeb/MakePayment.aspx", ""},
            {NULL_POINTER, "Medium", "/ZigguratUtilityWeb/MakePayment.aspx", ""},
            {SQLI, "Info", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", ""},
            {UNCHECKED_ERROR, "Info", "/ZigguratUtilityWeb/App_Code/DBUtil.cs", ""}
    };


    @Test
    public void fortifyScanTest() {
        ScanComparisonUtils.compare(fortify360Results, ScanLocationManager.getRoot() +
                "Static/Fortify/ZigguratUtility.fpr");
    }
}
