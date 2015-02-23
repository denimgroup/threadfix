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
package com.denimgroup.threadfix.csv2ssl.parser;

import com.denimgroup.threadfix.csv2ssl.checker.Configuration;
import com.denimgroup.threadfix.csv2ssl.util.Option;
import com.denimgroup.threadfix.csv2ssl.util.Strings;
import org.junit.Before;
import org.junit.Test;

/**
 * Created by mac on 12/3/14.
 */
public class FormatParserTests {

    @Before
    public void init() {
        Configuration.reset();
    }

    @Test
    public void testBasicSuccessCase() {
        String formatString = Strings.CWE + "," + Strings.PARAMETER;
        Option<String[]> stringOption = parseFromString(formatString);

        assert stringOption.isValid() : "Unexpectedly got invalid for " + formatString;
    }

    @Test
    public void testDowncaseSuccessCase() {
        String formatString = Strings.CWE.toLowerCase() + "," + Strings.NATIVE_ID.toLowerCase();
        Option<String[]> stringOption = parseFromString(formatString);

        assert stringOption.isValid() : "Unexpectedly got invalid for " + formatString;
    }

    @Test
    public void testSpaceSuccessCase() {
        String formatString = Strings.CWE.toLowerCase() + ", " + Strings.NATIVE_ID.toLowerCase();
        Option<String[]> stringOption = parseFromString(formatString);

        assert stringOption.isValid() : "Unexpectedly got invalid for " + formatString;
    }

    private Option<String[]> parseFromString(String formatString) {
        return FormatParser.getHeaders(new String[] {Strings.FORMAT_STRING + formatString});
    }

}
