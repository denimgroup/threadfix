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

import org.junit.Test;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 3/5/15.
 */
public class FortifyFilterSetTests {

    @Test
    public void testFilterSetApplication() {
        FortifyFilterSet filterSet = getFortifyFilterSet();

        String result = filterSet.getResult(map(VulnKey.CATEGORY, "Denial of Service"), 0F, 0F);

        assert "Code Quality".equals(result) : "Got " + result + " instead of Code Quality";
    }

    @Test
    public void testUnreleasedResource() {
        FortifyFilterSet filterSet = getFortifyFilterSet();

        String result = filterSet.getResult(map(VulnKey.KINGDOM, "Code Quality", VulnKey.CATEGORY, "Unreleased Resource"), 0F, 0F);

        assert "High".equals(result) : "Got " + result + " instead of Code Quality";
    }

    private FortifyFilterSet getFortifyFilterSet() {
        FilterTemplateXmlParser parsedResult = FilterTemplateXmlTests.getParsedResult();

        return parsedResult.filterSet;
    }

    @Test
    public void testFilterSetOrder() {
        FortifyFilterSet filterSet = getFortifyFilterSet();

        Map<VulnKey, String> multipleValueMap = map(
                VulnKey.ANALYSIS, "Low",
                VulnKey.CATEGORY, "Unreleased Resource"
        );

        String result = filterSet.getResult(multipleValueMap, 4F, 4F);

        assert "Low".equals(result) : "Got " + result + " instead of Low.";
    }

    Map<VulnKey, String> emptyMap = map();

    @Test
    public void testImpactAndLikelihoodFilters() {

        FortifyFilterSet filters = getFortifyFilterSet();

        float [][] criticals = new float[][] {
                { 5F, 5F },
                { 4F, 4F },
                { 3.5F, 3.5F }
        };
        test(filters, "Critical", criticals);

        float [][] highs = new float[][] {
                { 3F, 5F },
                { 3F, 4F },
                { 3F, 3.5F },
                { 3F, 3.4F},
                { 5F, 3.4F },
                { 4F, 3.4F }
        };
        test(filters, "High", highs);

        float [][] mediums = new float[][] {
                { 2.4F, 5F },
                { 3F, 2.4F },
                { 2.4F, 3.5F },
                { 5F, 2.4F },
                { 4F, 2.4F },
                { 2.5F, 2.4F },
                { 2, 2 }
        };
        test(filters, "Medium", mediums);

        float [][] lows = new float[][] {
                { 1.0F, 5F },
                { 0, 5 },
                { 5, 0 },
                { 1.9F, 1.9F },
        };
        test(filters, "Low", lows);
    }

    private void test(FortifyFilterSet filters, String expected, float[][] criticals) {
        for (float[] pair : criticals) {
            String result = filters.getResult(emptyMap, pair[0], pair[1]);

            assert expected.equals(result) :
                    "Got " + result + " instead of " + expected +
                            " for " + pair[0] + ", " + pair[1];
        }
    }

    @Test
    public void testBasicTaint() {
        FortifyFilter filter = new FortifyFilter(map(
                FilterKey.SEVERITY, "Critical",
                FilterKey.QUERY, "taint:serialized"
        ));

        String result = filter.getFinalSeverity(map(VulnKey.TAINT, "Serialized"), 0f, 0f);

        assert "Critical".equals(result) : "Expected Critical, got " + result;
    }

    @Test
    public void testMultipleTaintFail() {
        FortifyFilter filter = new FortifyFilter(map(
                FilterKey.SEVERITY, "Critical",
                FilterKey.QUERY, "taint:database, serialized"
        ));

        String result = filter.getFinalSeverity(map(VulnKey.TAINT, "SERIALIZED"), 0f, 0f);

        assert null == result : "Expected null, got " + result;
    }

    @Test
    public void testMultipleTaintSuccess() {
        FortifyFilter filter = new FortifyFilter(map(
                FilterKey.SEVERITY, "Critical",
                FilterKey.QUERY, "taint:serialized, xss"
        ));

        String result = filter.getFinalSeverity(map(VulnKey.TAINT, "SERIALIZED, XSS"), 0f, 0f);

        assert "Critical".equals(result) : "Expected Critical, got " + result;
    }

    @Test
    public void testHiddenFilter() {

        FilterTemplateXmlParser filterTemplateResult = FilterTemplateXmlTests.getParsedResult("fortify/filtertemplate-hide.xml");
        FortifyFilterSet set = filterTemplateResult.filterSet;

        String result = set.getResult(map(VulnKey.KINGDOM, "encapsulation"), 0f, 0f);

        assert FortifyFilter.HIDE.equals(result) :
                "Expected " + FortifyFilter.HIDE + " but got " + result;

    }

}
