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

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.map;

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
        String query = "likelihood:[0,5.0] AND impact:[0,5.0]";

        Threshold impact = new Threshold(query, "Likelihood");
        Threshold likelihood= new Threshold(query, "Impact");

        assert impact.high > 4.9 :
                "Was expecting impact high threshold of 5.0, got " + impact.high;
        assert impact.low < 0.1 :
                "Was expecting impact low threshold of 0, got " + impact.low;
        assert likelihood.low < 0.1 :
                "Was expecting likelihood low threshold of 0, got " + likelihood.low;
        assert likelihood.high > 4.9 :
                "Was expecting likelihood high threshold of 5.0, got " + likelihood.high;
    }

    Map<VulnKey, String> emptyMap = map();

    @Test
    public void testThresholdApplication() {
        FortifyFilter filter = getFilterFromQuery("likelihood:[0,5.0] AND impact:[0,5.0]");

        String finalSeverity = filter.getFinalSeverity(emptyMap, 3F, 5F);

        assert "Warning".equals(finalSeverity) :
                "Expected Critical, got " + finalSeverity;
    }

    @Test
    public void testFullCategoryNotParsed() {
        FortifyFilter filter = getFilterFromQuery("category:Unreleased Resource");

        assert filter.myFields.containsKey(VulnKey.CATEGORY) :
                "Didn't have normal category.";
        assert !filter.myFields.containsKey(VulnKey.FULL_CATEGORY) :
                "Had full category :(";
    }

    @Test
    public void testFullCategoryParsed() {
        FortifyFilter filter = getFilterFromQuery("category:Unreleased Resource: Database");

        assert !filter.myFields.containsKey(VulnKey.CATEGORY) :
                "Had normal category.";
        assert filter.myFields.containsKey(VulnKey.FULL_CATEGORY) :
                "Didn't have full category :(";
    }

    @Test
    public void testNegativeCategorySuccess() {
        FortifyFilter filter = getFilterFromQuery("category:!Unreleased Resource");

        String result = filter.getFinalSeverity(map(VulnKey.CATEGORY, "Test Resource"), 0f, 0f);

        assert "Warning".equals(result) : "Expected Critical, got " + result;
    }

    @Test
    public void testNegativeCategoryFailure() {
        FortifyFilter filter = getFilterFromQuery("category:!Unreleased Resource");

        String result = filter.getFinalSeverity(map(VulnKey.CATEGORY, "Unreleased Resource"), 0f, 0f);

        assert null == result : "Expected null, got " + result;
    }

    @Test
    public void testOldStyleFilters() {
        FortifyFilter filter = getFilterFromQuery("confidence:[4,5] severity:(3,5]");

        String result = filter.getFinalSeverity(map(VulnKey.CATEGORY, "Unreleased Resource"),
                map("Confidence", 4f, "Severity", 5f));

        assert "Warning".equals(result) : "Expected Warning, got " + result;
    }

    @Test
    public void testInclusiveExclusiveFilters() {
        test("confidence:[4,5]", 4f, true);
        test("confidence:(4,5]", 4f, false);
        test("confidence:[4,5]", 5f, true);
        test("confidence:[4,5)", 5f, false);
    }

    void test(String query, float confidence, boolean shouldSucceed) {
        FortifyFilter filter = getFilterFromQuery(query);

        String result = filter.getFinalSeverity(map(VulnKey.CATEGORY, "Fake Resource"),
                map("Confidence", confidence));

        if (shouldSucceed) {
            assert "Warning".equals(result) : "Expected Warning, got " + result + " for " + query + " and value " + confidence;
        } else {
            assert result == null : "Expected null, got " + result + " for " + query + " and value " + confidence;
        }
    }

    private FortifyFilter getFilterFromQuery(String query) {
        Map<FilterKey, String> filterMap = map(
                FilterKey.SEVERITY, "Warning",
                FilterKey.QUERY, query
        );

        return new FortifyFilter(filterMap);
    }

    @Test
    public void testBasicOr() {
        String query = "category:access control\\: database OR " +
                "category:password management\\: empty password in configuration file";

        FortifyFilter filter = getFilterFromQuery(query);

        String finalSeverity = filter.getFinalSeverity(
                map(VulnKey.FULL_CATEGORY, "access control: database"),
                new HashMap<String, Float>());

        assert "Warning".equals(finalSeverity) :
                "Expected Warning for access control: database, got " + finalSeverity;

        finalSeverity = filter.getFinalSeverity(
                map(VulnKey.FULL_CATEGORY, "password management: empty password in configuration file"),
                new HashMap<String, Float>());

        assert "Warning".equals(finalSeverity) :
                "Expected Warning for password management, got " + finalSeverity;
    }

    @Test
    public void testNeverApplicableFilter() {
        String query = "category:access control\\: database AND " +
                "category:password management\\: empty password in configuration file OR " +
                "kingdom:security features AND " +
                "kingdom:environment";

        FortifyFilter filter = getFilterFromQuery(query);

        String finalSeverity = filter.getFinalSeverity(
                map(
                        VulnKey.FULL_CATEGORY, "Password Management: Empty Password in Configuration File",
                        VulnKey.CATEGORY, "Password Management",
                        VulnKey.KINGDOM, "Environment"
                ),
                new HashMap<String, Float>());

        assert finalSeverity == null : "Didn't get null, got " + finalSeverity;
    }


}
