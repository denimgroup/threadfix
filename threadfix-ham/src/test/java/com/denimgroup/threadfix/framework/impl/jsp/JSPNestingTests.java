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

package com.denimgroup.threadfix.framework.impl.jsp;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class JSPNestingTests {

    @Test
    public void test7LevelNesting() {
        JSPMappings mappings = new JSPMappings(ResourceManager.getFile("code.jsp/nesting"));

        for (Endpoint endpoint : mappings) {
            assertTrue("param1 was missing from " + endpoint.getFilePath(),
                    endpoint.getParameters().contains("param1"));
        }
    }

    // this should throw StackOverflowException if cycles aren't recognized properly
    @Test
    public void testCycle() {
        JSPMappings mappings = new JSPMappings(ResourceManager.getFile("code.jsp.cycle"));

        for (Endpoint endpoint : mappings) {
            assertTrue("param1 was missing from " + endpoint.getFilePath(),
                    endpoint.getParameters().contains("test"));
        }
    }

}
