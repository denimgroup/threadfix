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
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by mcollins on 3/5/15.
 */
public class FortifyFilterTests {

    @Test
    public void testCategoryFilterNull() {
        String test = getFilterResult("test");

        assert test == null : "Got non-null result for dummy category.";
    }

    @Test
    public void testCategoryFilterNotNull() {
        String result = getFilterResult("use after free");

        assert "Critical".equals(result) : "Got " + result + " instead of Critical.";
    }

    @Test
    public void testCategoryFilterUpperCase() {
        String result = getFilterResult("Use After Free");

        assert "Critical".equals(result) : "Got " + result + " instead of Critical.";
    }

    private String getFilterResult(String value) {
        FortifyFilter filter = getFortifyFilter();

        return filter.getFinalSeverity(map(VulnKey.CATEGORY, value), 0F, 0F);
    }

    private FortifyFilter getFortifyFilter() {
        Map<FilterKey, String> filterMap = map(
                FilterKey.SEVERITY, "Critical",
                FilterKey.QUERY, "category:\"use after free\""
        );

        return new FortifyFilter(filterMap);
    }

    @Test
    public void testParseAndQuery() {
        FortifyFilter fortifyFilter = getAndedFortifyFilter();

        String category = fortifyFilter.myFields.get(VulnKey.CATEGORY);
        String kingdom  = fortifyFilter.myFields.get(VulnKey.KINGDOM);

        assert category.equals("unreleased resource") :
                "Got " + category + " instead of unreleased resource";
        assert kingdom.equals("code quality") :
                "Got " + kingdom + " instead of code quality";
    }

    @Test
    public void testApplyAndQueryValid() {
        FortifyFilter filter = getAndedFortifyFilter();

        Map<VulnKey, String> factMap = map(
                VulnKey.CATEGORY, "Unreleased Resource",
                VulnKey.KINGDOM, "Code Quality"
        );

        String result = filter.getFinalSeverity(factMap, 0F, 0F);

        assert "Critical".equals(result) : "Expected Critical, got " + result;
    }

    @Test
    public void testApplyAndQueryHalfValid() {
        FortifyFilter filter = getAndedFortifyFilter();

        Map<VulnKey, String> factMap = map(
                VulnKey.CATEGORY, "Unreleased Resource 2",
                VulnKey.KINGDOM, "Code Quality"
        );

        String result = filter.getFinalSeverity(factMap, 0F, 0F);

        assert result == null : "Expected null, got " + result;

    }

    private FortifyFilter getAndedFortifyFilter() {
        Map<FilterKey, String> filterMap = map(
                FilterKey.SEVERITY, "Critical",
                FilterKey.QUERY, "category:\"unreleased resource\" AND kingdom:\"code quality\""
        );

        return new FortifyFilter(filterMap);
    }

    @Test
    public void testThresholdParsing() {
        Map<FilterKey, String> filterMap = map(
                FilterKey.SEVERITY, "Critical",
                FilterKey.QUERY, "likelihood:[0,5.0] AND impact:[0,5.0]"
        );

        FortifyFilter filter = new FortifyFilter(filterMap);

        assert filter.impactHighThreshold > 4.9 :
                "Was expecting impact high threshold of 5.0, got " + filter.impactHighThreshold;
        assert filter.impactLowThreshold < 0.1 :
                "Was expecting impact low threshold of 0, got " + filter.impactLowThreshold;
        assert filter.likelihoodLowThreshold < 0.1 :
                "Was expecting likelihood low threshold of 0, got " + filter.likelihoodLowThreshold;
        assert filter.likelihoodHighThreshold > 4.9 :
                "Was expecting likelihood high threshold of 5.0, got " + filter.likelihoodHighThreshold;
    }

    Map<VulnKey, String> emptyMap = newMap();

    @Test
    public void testThresholdApplication() {
        Map<FilterKey, String> filterMap = map(
                FilterKey.SEVERITY, "Critical",
                FilterKey.QUERY, "likelihood:[0,5.0] AND impact:[0,5.0]"
        );

        FortifyFilter filter = new FortifyFilter(filterMap);

        String finalSeverity = filter.getFinalSeverity(emptyMap, 3F, 5F);

        assert "Critical".equals(finalSeverity) :
                "Expected Critical, got " + finalSeverity;
    }

}
