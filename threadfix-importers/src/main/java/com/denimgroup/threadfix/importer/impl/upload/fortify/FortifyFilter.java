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

    // TODO compile these into patterns
    //                    impact:[0,5.0]
    String impactRegexLow = "impact:\\[([0-9\\.]+),[0-9\\.]+\\]";
    String impactRegexHigh = "impact:\\[[0-9\\.]+,([0-9\\.]+)\\]";
    String likelihoodRegexLow = "likelihood:\\[([0-9\\.]+),[0-9\\.]+\\]";
    String likelihoodRegexHigh = "likelihood:\\[[0-9\\.]+,([0-9\\.]+)\\]";

    float impactLowThreshold, impactHighThreshold,
            likelihoodLowThreshold, likelihoodHighThreshold;

    private void parseFields(String query) {

        for (VulnKey key : VulnKey.values()) {
            String result = RegexUtils.getRegexResult(query, key.pattern);
            if (result != null) {
                myFields.put(key, result);
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

    public String getFinalSeverity(Map<VulnKey, String> vulnInfo, float impact, float likelihood) {

        boolean matches = false, miss = false;

        for (VulnKey key : VulnKey.values()) {

            String theirValue = vulnInfo.get(key);
            String myValue = myFields.get(key);

            if (myValue != null) { // we need to filter on this value
                if (myValue.equalsIgnoreCase(theirValue)) {
                    // this means we've passed at least one condition
                    // we can't break here because there may be multiple conditions
                    matches = true;
                } else {
                    // if we miss any one filter, fail the test
                    miss = true;
                    break;
                }
            }
        }

        // TODO incorporate custom impact + likelihood filtering

        return matches && !miss ? target : null;
    }
}
