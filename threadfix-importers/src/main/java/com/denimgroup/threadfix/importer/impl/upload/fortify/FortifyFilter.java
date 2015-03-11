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

import com.denimgroup.threadfix.framework.util.RegexUtils;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.newMap;
import static com.denimgroup.threadfix.importer.impl.upload.fortify.FilterResult.*;

/**
 * Created by mcollins on 3/5/15.
 */
public class FortifyFilter {

    final String query, target;

    public FortifyFilter(Map<FilterKey, String> map) {
        query = map.get(FilterKey.QUERY);
        target = map.get(FilterKey.SEVERITY);

        parseFields(query);
    }

    Map<VulnKey, String> myFields = newMap();
    Map<VulnKey, String> myNegativeFields = newMap();

    Threshold impact   = new Threshold("Impact"),
            likelihood = new Threshold("Likelihood"),
            confidence = new Threshold("Confidence"),
            severity   = new Threshold("Severity");

    public static void main(String[] args) {
        System.out.println(3.5 == 3.5);
    }

    private void parseFields(String query) {

        if (query.contains(" AND ")) {
            String[] subqueries = query.split(" AND ");
            for (String subquery : subqueries) {
                parseFields(subquery);
            }
            return;
        }

        for (VulnKey key : VulnKey.values()) {
            String result = RegexUtils.getRegexResult(query, key.pattern);
            if (result != null) {
                String replaced = result.replaceAll("\\\\:", ":");
                if (replaced.charAt(0) == '!') {
                    myNegativeFields.put(key, replaced.substring(1));
                } else {
                    myFields.put(key, replaced);
                }
            }
        }

        if (!impact.isValid()) impact.initialize(query);
        if (!confidence.isValid()) confidence.initialize(query);
        if (!severity.isValid()) severity.initialize(query);
        if (!likelihood.isValid()) likelihood.initialize(query);
    }

    public String getFinalSeverity(Map<VulnKey, String> vulnInfo, float likelihood, float impact) {
        Map<String, Float> numberMap = map(
                "Impact", impact,
                "Likelihood", likelihood
        );

        return getFinalSeverity(vulnInfo, numberMap);
    }

    public String getFinalSeverity(Map<VulnKey, String> vulnInfo, Map<String, Float> numberMap) {

        // basic, positive matching
        FilterResult result = getStringResult(vulnInfo, myFields);

        // negative matching
        FilterResult negativeResult = getStringResult(vulnInfo, myNegativeFields);
        if (negativeResult == MISS) {
            negativeResult = MATCH;
        } else if (negativeResult == MATCH) {
            negativeResult = MISS;
        }

        // threshold matching
        FilterResult thresholdResult = passesThresholds(numberMap);

        return getCombinedResult(result, negativeResult, thresholdResult) == MATCH ? target : null;
    }

    private FilterResult getCombinedResult(FilterResult... results) {
        FilterResult finalResult = NO_MATCH;

        for (FilterResult result : results) {
            if (result == MISS) {
                finalResult = MISS;
                break;
            } else if (result == MATCH) {
                finalResult = MATCH;
            }
        }

        return finalResult;
    }


    private FilterResult getStringResult(Map<VulnKey, String> vulnInfo, Map<VulnKey, String> myFields) {
        FilterResult result = NO_MATCH;

        for (VulnKey key : myFields.keySet()) {

            String theirValue = vulnInfo.get(key);
            String myValue = myFields.get(key);

            if (myValue != null) { // we need to filter on this value
                if (VulnKey.TAINT == key && theirValue != null) {

                    if (theirValue.toLowerCase().contains(myValue.toLowerCase())) {
                        result = MATCH;
                    } else {
                        result = MISS;
                        break;
                    }
                } else if (myValue.equalsIgnoreCase(theirValue)) {
                    // this means we've passed at least one condition
                    // we can't break here because there may be multiple conditions
                    result = MATCH;
                } else {
                    // if we miss any one filter, fail the test
                    result = MISS;
                    break;
                }
            }
        }
        return result;
    }

    private FilterResult passesThresholds(Map<String, Float> numberMap) {

        FilterResult[] individualResults = {
                impact.check(numberMap.get("Impact")),
                confidence.check(numberMap.get("Confidence")),
                likelihood.check(numberMap.get("Likelihood")),
                severity.check(numberMap.get("Severity"))
        };

        return getCombinedResult(individualResults);
    }
}
