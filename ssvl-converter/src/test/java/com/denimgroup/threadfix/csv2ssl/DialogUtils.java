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

import com.denimgroup.threadfix.csv2ssl.util.InteractionUtils;

import java.io.BufferedReader;
import java.io.StringReader;

/**
 * Created by mcollins on 2/12/15.
 */
public class DialogUtils {

    private DialogUtils(){}

    public static String testDialog(String dialog) {
        InteractionUtils.reader = new BufferedReader(new StringReader(dialog));

        String s = Main.doConfigurationAndParsing(new String[]{});

        assert s.contains("<Vulnerability") : "Didn't have any vulnerabilities.";

        return s;
    }
}
