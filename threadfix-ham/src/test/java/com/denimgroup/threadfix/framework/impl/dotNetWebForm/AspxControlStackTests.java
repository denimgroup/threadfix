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

/**
 * Created by mac on 10/23/14.
 */
public class AspxControlStackTests {

    private AspxControl
            testControl1 = new AspxControl("test1", "test1"),
            testControl2 = new AspxControl("test2", "test2"),
            nullControl1 = new AspxControl("test", null);

    @Test
    public void testBasicAutomaticIdGeneration() {
        AspxControlStack stack = new AspxControlStack();

        stack.add(testControl1);
        stack.add(testControl2);

        assert stack.generateCurrentParamName().equals("ctl00$test1$test2");
    }
    @Test
    public void testNullIdGeneration() {
        AspxControlStack stack = new AspxControlStack();

        stack.add(nullControl1);
        stack.removeLast();
        stack.add(nullControl1);
        stack.removeLast();
        stack.add(nullControl1);
        stack.add(testControl2);

        assert stack.generateCurrentParamName().equals("ctl00$ctl02$test2");
    }


}
