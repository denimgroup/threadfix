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

        String result = filterSet.getResult(multipleValueMap, 0F, 0F);

        assert "Low".equals(result) : "Got " + result + " instead of Low.";

    }

}
