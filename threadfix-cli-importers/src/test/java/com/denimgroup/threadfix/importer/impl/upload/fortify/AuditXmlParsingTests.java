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
package com.denimgroup.threadfix.importer.impl.upload.fortify;

import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import org.junit.Test;

import java.io.InputStream;

/**
 * Created by mcollins on 2/16/15.
 */
public class AuditXmlParsingTests {

    @Test
    public void testNotAnIssue() {
        FortifyAuditXmlParser timeParser = getParsedResult();

        assert timeParser.suppressedIds.contains("F4B239E280210E3ADF7044526BBE3F13") :
                "Didn't have F4B239E280210E3ADF7044526BBE3F13";
    }

    @Test
    public void testSuppressed() {
        FortifyAuditXmlParser timeParser = getParsedResult();

        assert timeParser.suppressedIds.contains("7FB3F7B4BF0EBD97F3BA5FEA8BC0E682") :
                "Didn't have 7FB3F7B4BF0EBD97F3BA5FEA8BC0E682";
    }

    private FortifyAuditXmlParser getParsedResult() {
        String fileName = "fortify/full-audit.xml";
        return getFortifyAuditXmlParser(fileName);
    }

    @Test
    public void testv4Suppressed() {
        FortifyAuditXmlParser parser = getFortifyAuditXmlParser("fortify/audit-v4.xml");

        assert parser.suppressedIds.contains("F6B2D27A23F8A82998D2264A3939E3FC") :
                "Didn't have F6B2D27A23F8A82998D2264A3939E3FC";

    }

    private FortifyAuditXmlParser getFortifyAuditXmlParser(String fileName) {
        InputStream auditXmlStream = AuditXmlParsingTests.class.getClassLoader().getResourceAsStream(fileName);

        FortifyAuditXmlParser timeParser = new FortifyAuditXmlParser();
        ScanUtils.readSAXInput(timeParser, AbstractChannelImporter.FILE_CHECK_COMPLETED, auditXmlStream);
        return timeParser;
    }
}
