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
package com.denimgroup.threadfix.importer.impl.upload.fortify;

import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import org.junit.Test;

import java.io.InputStream;
import java.util.List;

/**
 * Created by mcollins on 3/5/15.
 */
public class FilterTemplateXmlTests {

    @Test
    public void testParseRightNumberOfFilters() {
        int expectedTotal = 53;

        FilterTemplateXmlParser result = getParsedResult();

        int actualSize = result.filterSet.filters.size();
        assert actualSize == expectedTotal :
                "Got " + actualSize + " but was expecting " + expectedTotal;
    }

    @Test
    public void testCorrectQueries() {
        String[] firstQueries = new String[] {
                "taint:\"database, number\"",
                "[fortify priority order]:critical",
                "[fortify priority order]:high",
                "[fortify priority order]:medium"
        };

        FilterTemplateXmlParser result = getParsedResult();

        List<FortifyFilter> filters = result.filterSet.filters;

        for (int i = 0; i < firstQueries.length; i++) {
            String actualQuery = filters.get(i).query;
            assert actualQuery.equals(firstQueries[i]) :
                    i + ": expected " + firstQueries[i] + ", got " + actualQuery;
        }
    }

    @Test
    public void testCorrectSeverities() {
        String[] firstSeverities = new String[] {
                "Code Quality",
                "Critical",
                "High",
                "Medium"
        };

        FilterTemplateXmlParser result = getParsedResult();

        List<FortifyFilter> filters = result.filterSet.filters;

        for (int i = 0; i < firstSeverities.length; i++) {
            String actualSeverity = filters.get(i).target;
            assert actualSeverity.equals(firstSeverities[i]) :
                    i + ": expected " + firstSeverities[i] + ", got " + actualSeverity;
        }
    }


    private FilterTemplateXmlParser getParsedResult() {
        InputStream auditXmlStream = AuditXmlParsingTests.class.getClassLoader().getResourceAsStream("fortify/filtertemplate.xml");

        FilterTemplateXmlParser parser = new FilterTemplateXmlParser();
        ScanUtils.readSAXInput(parser, AbstractChannelImporter.FILE_CHECK_COMPLETED, auditXmlStream);
        return parser;
    }

}
