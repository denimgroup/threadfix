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

/**
 * Created by mcollins on 3/5/15.
 */
public class FortifyFilterSetTests {

    @Test
    public void testFilterSetApplication() {
        FilterTemplateXmlParser parsedResult = FilterTemplateXmlTests.getParsedResult();

        FortifyFilterSet filterSet = parsedResult.filterSet;

        String result = filterSet.getResult("Denial of Service");

        assert "Code Quality".equals(result) : "Got " + result + " instead of Code Quality";
    }


}
