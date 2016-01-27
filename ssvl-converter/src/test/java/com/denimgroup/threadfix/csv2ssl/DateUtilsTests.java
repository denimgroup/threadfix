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

package com.denimgroup.threadfix.csv2ssl;

import com.denimgroup.threadfix.csv2ssl.util.DateUtils;
import org.junit.Test;

import java.text.SimpleDateFormat;

/**
 * Created by mcollins on 12/10/2014.
 */
public class DateUtilsTests {

    SimpleDateFormat OURS = DateUtils.OUR_DATE_FORMAT, THEIRS = new SimpleDateFormat("dd/MM/yyyy");

    String[][] tests = {
            { "05/10/2014", "2014-10-05 00:00:00" },
            { "3/11/2014",  "2014-11-03 00:00:00" },
    };

    @Test
    public void testConversions() {
        for (String[] test : tests) {
            test(test[0], test[1]);
        }
    }

    private void test(String dateString, String prefix) {

        DateUtils.THEIR_DATE_FORMAT = THEIRS;
        DateUtils.OUR_DATE_FORMAT = OURS;

        String converted = DateUtils.toOurFormat(dateString);

        assert converted.startsWith(prefix) :
                dateString + " converted to " + converted + " which didn't start with " + prefix;
    }


}
