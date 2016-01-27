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

package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ParserUtils;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;

import static com.denimgroup.threadfix.importer.TestConstants.*;
import static org.junit.Assert.assertTrue;

/**
 * Created by denimgroup on 2/10/14.
 */
public class W3afScanTest extends TransactionalTest {

    public final static String[][] w3afResults = new String[] [] {
            {EVAL_INJECTION,"High", "/demo/EvalInjection2.php","command"},
            {XSS, "High", "/demo/XSS-cookie.php", "cookie"},
            {LDAP_INJECTION,"High", "/demo/LDAPInjection2.php","username"},
            {OS_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
            {SQLI,"High", "/demo/SQLI2.php","username"},
            {XPATH_INJECTION,"Medium", "/demo/XPathInjection2.php","password"},
            {XPATH_INJECTION,"Medium", "/demo/XPathInjection2.php","username"},
            {XSS,"Medium", "/demo/EvalInjection2.php","command"},
            {XSS,"Medium", "/demo/XSS-reflected2.php","username"},
            {FORMAT_STRING_INJECTION,"Medium", "/demo/FormatString2.php","name"},
            {FORCED_BROWSING,"Info", "/demo.zip",""},
            {FORCED_BROWSING,"Info", "/demo/PredictableResource.php.bak",""},

    };

    public final static String[][] w3afResultsV21 = new String[] [] {
            {SQLI,"High","/bank/login.aspx","passw"},
            {SQLI,"High","/bank/login.aspx","uid"},
            {SQLI,"High","/subscribe.aspx","txtEmail"},
            {XSS,"Medium","/bank/login.aspx","uid"},
            {XSS,"Medium","/comment.aspx","name"},
            {XSS,"Medium","/search.aspx","txtSearch"},
            {XSS,"Medium","/subscribe.aspx","txtEmail"}
    };

    @Test
    public void w3afScanTest() {
        ScanComparisonUtils.compare(w3afResults, ScanLocationManager.getRoot() +
                "Dynamic/w3af/w3af-demo-site.xml");
    }

    @Test
    public void w3afScanTestV21() {
        ScanComparisonUtils.compare(w3afResultsV21, ScanLocationManager.getRoot() +
                "Dynamic/w3af/w3af-ver_172.xml");
    }

    @Test
    public void w3afScanTestNewFields() {
        Scan scan = ParserUtils.getScan("Dynamic/w3af/w3af-ver_172.xml");
        String description, detail, recommendation;
        boolean descFound = false, detailFound = false, recommendationFound = false;

        for (Finding finding : scan) {
            description = finding.getLongDescription();
            detail = finding.getScannerDetail();
            recommendation = finding.getScannerRecommendation();

            if (description != null && !description.isEmpty())
                descFound = true;
            if (detail != null && !detail.isEmpty())
                detailFound = true;
            if (recommendation != null && !recommendation.isEmpty())
                recommendationFound = true;
        }

        assertTrue("No finding found with LongDescription.", descFound);
        assertTrue("No finding found with ScannerDetail.", detailFound);
        assertTrue("No finding found with ScannerRecommendation.", recommendationFound);
    }


}

