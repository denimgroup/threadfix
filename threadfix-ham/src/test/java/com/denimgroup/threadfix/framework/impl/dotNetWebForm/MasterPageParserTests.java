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

import com.denimgroup.threadfix.framework.TestConstants;
import org.junit.Test;

import java.io.File;
import java.util.Map;

/**
 * Created by mac on 10/27/14.
 */
public class MasterPageParserTests {

    @Test
    public void testBasic() {
        Map<String, AspxParser> masterFileMap =
                MasterPageParser.getMasterFileMap(new File(TestConstants.WEB_FORMS_MODIFIED));

        assert masterFileMap.containsKey("Site.Master") :
                "Didn't contain Site.Master : " + masterFileMap;
        assert masterFileMap.get("Site.Master").parameters.size() > 0 :
                "Site.Master didn't have parameters: " + masterFileMap.get("Site.Master");
    }

}
