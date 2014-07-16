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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
        assert mappings.getActionForNameAndMethod("Index", "GET") != null :
                "Mappings didn't contain Index. They had " + mappings.getActions().iterator().next();
    }

    @Test
    public void testControllerWithPostAttribute() {
        DotNetControllerMappings mappings =
                DotNetControllerParser.parse(ResourceManager.getFile("code.dotNet.mvc/AttributesController.cs"));

        assert mappings.getControllerName() != null :
                "Controller name was null.";
        assert mappings.getControllerName().equals("Account") :
                "Controller name was " + mappings.getControllerName() + " but should have been Account.";
        assert mappings.getActionForNameAndMethod("Login", "POST") != null :
                "Mappings didn't contain Login with POST.";
    }

    @Test
    public void testRestController() {
        DotNetControllerMappings mappings =
                DotNetControllerParser.parse(ResourceManager.getFile("code.dotNet.mvc/RestController.cs"));

        assert mappings.getControllerName() != null :
                "Controller name was null.";
        assert mappings.getControllerName().equals("Students") :
                "Controller name was " + mappings.getControllerName() + " but should have been Students.";
        assert mappings.getActionForNameAndMethod("Get", "GET") != null :
                "Mappings didn't contain Get with GET.";
    }

    @Test
    public void testAttributesControllerActionSizeAndMethods() {
        DotNetControllerMappings mappings =
                DotNetControllerParser.parse(ResourceManager.getFile("code.dotNet.mvc/AttributesController.cs"));

        List<String> expectedActions = Arrays.asList(
                "Login",
                "Login",
                "LogOff",
                "Register",
                "Register",
                "Disassociate",
                "Manage",
                "Manage",
                "ExternalLogin",
                "ExternalLoginCallback",
                "ExternalLoginConfirmation",
                "ExternalLoginFailure",
                "ExternalLoginsList",
                "RemoveExternalLogins"
        ), expectedMethods = Arrays.asList(
                "GET",
                "POST",
                "POST",
                "GET",
                "POST",
                "POST",
                "GET",
                "POST",
                "POST",
                "GET",
                "POST",
                "GET",
                "GET",
                "GET"
        ), missing = new ArrayList<>(), extra = new ArrayList<>();

        assert expectedActions.size() == expectedMethods.size() :
                "Expected actions and methods didn't match up.";
        assert mappings.getControllerName() != null :
                "Controller name was null.";
        assert mappings.getControllerName().equals("Account") :
                "Controller name was " + mappings.getControllerName() + " but should have been Account.";


        for (int i = 0; i < expectedActions.size(); i++) {
            if (mappings.getActionForNameAndMethod(expectedActions.get(i), expectedMethods.get(i)) == null) {
                missing.add(expectedActions.get(i) + " " + expectedMethods.get(i));
            }
        }

        for (Action action : mappings.getActions()) {
            if (!expectedActions.contains(action.name)) {
                extra.add(action.name + " " + action.getMethod());
            }
        }

        if (!missing.isEmpty()) {
            System.out.println("Controller is missing methods : " + missing);
        }

        if (!extra.isEmpty()) {
            System.out.println("Controller has extra methods : " + extra);
        }

        assert missing.isEmpty() && extra.isEmpty() : "Wrong number of methods. See above logs.";

        assert mappings.getActions().size() == 14 :
                "The size was " + mappings.getActions().size() + " instead of 14.";

    }


}
