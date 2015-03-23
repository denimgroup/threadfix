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

import static com.denimgroup.threadfix.importer.impl.upload.fortify.FilterResult.*;

/**
 * Created by mcollins on 3/11/15.
 */
public class Threshold {

    float lowThreshold, highThreshold;

    final private String key;

    private static String
            lowRegex            = ":\\(([0-9\\.]+),[0-9\\.]+[\\]\\)]",
            lowInclusiveRegex   = ":\\[([0-9\\.]+),[0-9\\.]+[\\]\\)]",
            highRegex           = ":[\\[\\(][0-9\\.]+,([0-9\\.]+)\\)",
            highInclusiveRegex  = ":[\\[\\(][0-9\\.]+,([0-9\\.]+)\\]"
                    ;

    private boolean valid = false, inclusiveLow = false, inclusiveHigh = false;

    float low, high;

    public Threshold(String key) {
        this.key = key;
    }

    public void initialize(String query) {
        assert !valid : "Already initialized.";

        if (query.contains(key.toLowerCase())) {
            parse(query);
        }
    }

    public Threshold(String query, String key) {
        this.key = key;
        initialize(query);
    }

    private static float parseFloat(String query, String regex) {
        String bareResult = RegexUtils.getRegexResult(query, regex);
        return bareResult == null ? -2 : Float.valueOf(bareResult);
    }

    private void parse(String query) {

        String lowerKey = key.toLowerCase();

        low  = parseFloat(query, lowerKey + lowRegex);
        high = parseFloat(query, lowerKey + highRegex);

        if (low < -1) {
            low = parseFloat(query, lowerKey + lowInclusiveRegex);
            inclusiveLow = low > -1;
        }

        if (high < -1) {
            high = parseFloat(query, lowerKey + highInclusiveRegex);
            inclusiveHigh = high > -1;
        }

        valid = low > -1 && high > -1;

    }

    public boolean isValid() {
        return valid;
    }

    public FilterResult check(Float value) {
        FilterResult returnValue = NO_MATCH;

        if (valid && value != null) {
            boolean validHigh, validLow;
            if (inclusiveHigh) {
                validHigh = value <= high;
            } else {
                validHigh = value < high;
            }

            if (inclusiveLow) {
                validLow = value >= low;
            } else {
                validLow = value > low;
            }

            returnValue = validHigh && validLow ? MATCH : MISS;
        }

        return returnValue;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(key);

        if (valid) {
            builder.append(inclusiveLow ? "[" : "(")
                    .append(low)
                    .append(",")
                    .append(high)
                    .append(inclusiveHigh ? "]" : ")");

        } else {
            builder.append(" (N/A)");
        }
        return builder.toString();
    }
}
