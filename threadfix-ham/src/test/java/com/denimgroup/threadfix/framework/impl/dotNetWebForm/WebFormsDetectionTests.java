////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import org.junit.Test;

import java.io.File;

/**
 * Created by mac on 9/8/14.
 */
public class WebFormsDetectionTests {
    @Test
    public void testAll() {

        File rootFile = new File(TestConstants.WEB_FORMS_ROOT);

        assert rootFile.exists() : "File at " + TestConstants.WEB_FORMS_ROOT + " was invalid.";

        assert rootFile.isDirectory() : TestConstants.WEB_FORMS_ROOT + " wasn't a directory.";

        File[] files = rootFile.listFiles();

        assert files != null : "Files returned from listFiles() were null.";

        for (File file : files) {
            if (file.getName().startsWith(".") || file.isFile()) {
                continue;
            }

            System.out.println(file.getName());

            FrameworkType type = FrameworkCalculator.getType(file);

            assert type == FrameworkType.DOT_NET_WEB_FORMS
                    : "Got " + type + " instead of DOT_NET_WEB_FORMS for " + file;
        }
    }
}
