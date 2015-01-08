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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import org.junit.Test;

import java.io.File;

import static com.denimgroup.threadfix.framework.impl.dotNetWebForm.WebFormUtilities.getSampleProjects;

/**
 * Created by mac on 9/8/14.
 */
public class WebFormsDetectionTests {

    @Test
    public void testAll() {

        for (File file : getSampleProjects()) {

            System.out.println(file.getName());

            FrameworkType type = FrameworkCalculator.getType(file);

            assert type == FrameworkType.DOT_NET_WEB_FORMS
                    : "Got " + type + " instead of DOT_NET_WEB_FORMS for " + file;
        }
    }
}
