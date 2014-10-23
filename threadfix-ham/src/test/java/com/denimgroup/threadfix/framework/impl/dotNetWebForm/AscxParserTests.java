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

import org.junit.Test;

import java.io.File;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.framework.ResourceManager.getDotNetWebFormsFile;

/**
 * Created by mac on 10/22/14.
 */
public class AscxParserTests {

    @Test
    public void testLoadingAscxMap() {
        File aspxFile = getDotNetWebFormsFile("StudentsAddWithControl.aspx");
        File controlFile = getDotNetWebFormsFile("WebUserControl1.ascx");

        Map<String, AscxFile> controlMap = map("WebUserControl1", new AscxFile(controlFile));

        AspxUniqueIdParser parser = AspxUniqueIdParser.parse(aspxFile, controlMap);

        assert parser.includedControlMap.containsKey("custom:WebUserControl1") :
            "tagNameMap didn't contain custom:WebUserControl1: " + parser.includedControlMap;
    }


}
