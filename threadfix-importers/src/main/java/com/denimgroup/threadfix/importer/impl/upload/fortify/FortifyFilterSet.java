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

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 3/5/15.
 */
public class FortifyFilterSet {

    List<FortifyFilter> filters = list();

    public void addFilter(FortifyFilter filter) {
        filters.add(filter);
    }

    Map<String, String> legacyMap = map(
            "Hot", "4.0",
            "Warning", "3.0"
    );

    // the last applicable filter should be the one applied
    public String getResult(Map<VulnKey, String> vulnInfo, Map<String, Float> numberMap) {
        String result = null;

        for (FortifyFilter filter : filters) {
            String filterResult = filter.getFinalSeverity(vulnInfo, numberMap);
            if (filterResult != null) {
                result = filterResult;
            }
        }

        if (legacyMap.containsKey(result)) {
            result = legacyMap.get(result);
        }

        return result;
    }

    // overload for testing convenience
    public String getResult(Map<VulnKey, String> vulnInfo, float impact, float likelihood) {
        Map<String, Float> numberMap = map(
                "Impact", impact,
                "Likelihood", likelihood
        );

        return getResult(vulnInfo, numberMap);
    }


}
