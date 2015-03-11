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

import static com.denimgroup.threadfix.CollectionUtils.newMap;
import static com.denimgroup.threadfix.importer.impl.upload.fortify.FortifyFilter.Result.MATCH;
import static com.denimgroup.threadfix.importer.impl.upload.fortify.FortifyFilter.Result.MISS;
import static com.denimgroup.threadfix.importer.impl.upload.fortify.FortifyFilter.Result.NO_MATCH;

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

    // TODO compile these into patterns
    //                    impact:[0,5.0]
    String lowRegex =  "\\[([0-9\\.]+),[0-9\\.]+\\]";
    String highRegex = "\\[[0-9\\.]+,([0-9\\.]+)\\]";

    String impactRegexLow      = "impact:"     + lowRegex;
    String impactRegexHigh     = "impact:"     + highRegex;
    String likelihoodRegexLow  = "likelihood:" + lowRegex;
    String likelihoodRegexHigh = "likelihood:" + highRegex;

    float impactLowThreshold = -2, impactHighThreshold = -2,
            likelihoodLowThreshold = -2, likelihoodHighThreshold = -2;

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

        String impactLow = RegexUtils.getRegexResult(query, impactRegexLow);
        String impactHigh = RegexUtils.getRegexResult(query, impactRegexHigh);
        String likelihoodLow = RegexUtils.getRegexResult(query, likelihoodRegexLow);
        String likelihoodHigh = RegexUtils.getRegexResult(query, likelihoodRegexHigh);

        if (impactLow != null) {
            impactLowThreshold = Float.valueOf(impactLow);
        }
        if (impactHigh != null) {
            impactHighThreshold = Float.valueOf(impactHigh);
        }
        if (likelihoodHigh != null) {
            likelihoodHighThreshold = Float.valueOf(likelihoodHigh);
        }
        if (likelihoodLow != null) {
            likelihoodLowThreshold = Float.valueOf(likelihoodLow);
        }
    }

    enum Result {
        NO_MATCH, MATCH, MISS
    }

    public String getFinalSeverity(Map<VulnKey, String> vulnInfo, float impact, float likelihood) {

        // basic, positive matching
        Result result = getResult(vulnInfo, myFields);

        // negative matching
        Result negativeResult = getResult(vulnInfo, myNegativeFields);
        if (negativeResult == MISS) {
            negativeResult = MATCH;
        } else if (negativeResult == MATCH) {
            negativeResult = MISS;
        }

        // threshold matching
        Result thresholdResult = passesThresholds(impact, likelihood);

        return getCombinedResult(result, negativeResult, thresholdResult) == MATCH ? target : null;
    }

    private Result getCombinedResult(Result... results) {
        Result finalResult = NO_MATCH;

        for (Result result : results) {
            if (result == MISS) {
                finalResult = MISS;
                break;
            } else if (result == MATCH) {
                finalResult = MATCH;
            }
        }

        return finalResult;
    }


    private Result getResult(Map<VulnKey, String> vulnInfo, Map<VulnKey, String> myFields) {
        Result result = NO_MATCH;

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

    private Result passesThresholds(float impact, float likelihood) {

        Result result = NO_MATCH;

        if (likelihoodLowThreshold > -1 && likelihoodHighThreshold > -1) {
            if (likelihood >= likelihoodLowThreshold && likelihood <= likelihoodHighThreshold) {
                result = MATCH;
            } else {
                return MISS;
            }
        }
        if (impactLowThreshold > -1 && impactHighThreshold > -1) {
            if (impact >= impactLowThreshold && impact <= impactHighThreshold) {
                result = MATCH;
            } else {
                return MISS;
            }
        }

        return result;
    }
}
