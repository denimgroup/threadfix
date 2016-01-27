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

package com.denimgroup.threadfix.framework.impl.struts;

import java.io.File;
import java.util.Collection;
import java.util.Iterator;

public class StrutsConfigurationChecker {
    private static final String STRUTS_CONFIG_NAME = "struts.xml";
    private static final String STRUTS_PROPERTIES_NAME = "struts.properties";

    public static boolean check(Collection<File> files) {
        boolean foundStrutsConfigFile = false;

        for (Iterator iterator = files.iterator(); iterator.hasNext();) {
            File file = (File) iterator.next();
            if (file.getName().equals(STRUTS_CONFIG_NAME))
                foundStrutsConfigFile = true;
            if (file.getName().equals(STRUTS_PROPERTIES_NAME))
                foundStrutsConfigFile = true;
            if (foundStrutsConfigFile)
                break;
        }

        return foundStrutsConfigFile;
    }

}
