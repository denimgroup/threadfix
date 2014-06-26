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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

/**
 * Created by mac on 6/11/14.
 */
public class DotNetControllerParserTests {

    @Test
    public void testBasicController() {
        DotNetControllerMappings mappings =
                DotNetControllerParser.parse(ResourceManager.getFile("code.dotNet.mvc/ChatController.cs"));

        assert mappings.getControllerName() != null :
                "Controller name was null.";
        assert mappings.getControllerName().equals("Chat") :
                "Controller name was " + mappings.getControllerName() + " but should have been Chat.";
        assert mappings.getActions().size() == 1 :
                "The size was " + mappings.getActions().size() + " instead of 1.";
        assert mappings.getActions().contains("Index") :
                "Mappings didn't contain Index. They had " + mappings.getActions().iterator().next();

    }

    @Test
    public void testControllerWithAttributes() {

    }


}
