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
package com.denimgroup.threadfix.framework.impl.spring.auth;

import org.junit.Test;

/**
 * Created by mcollins on 3/31/15.
 */
public class InterceptUrlTests {

    @Test
    public void testMatchAll() {
        InterceptUrl url = new InterceptUrl("/**", "ROLE_USER");

        String[] tests = new String[] {
                "/simple",
                "/two/segments",
                "/path/with/lots/of/segments",
                "/"
        };

        for (String test : tests) {
            assert url.matches(test) : "Failed for " + test;
        }
    }

    @Test
    public void testSingleStarPositive() {
        InterceptUrl url = new InterceptUrl("/test/*/path", "ROLE_USER");

        String[] tests = new String[] {
                "/test/3/path",
                "/test/testString/path",
        };

        for (String test : tests) {
            assert url.matches(test) : "Failed for " + test;
        }
    }

    @Test
    public void testSingleStarNegative() {
        InterceptUrl url = new InterceptUrl("/test/*/path", "ROLE_USER");

        String[] tests = new String[] {
                "/test/path",
                "/test/testString/path/andSomethingElse",
                "/test/other/other/path",
                "/different/2/path"
        };

        for (String test : tests) {
            assert !url.matches(test) : "Succeeded for " + test;
        }
    }

    @Test
    public void testMixedStarsPositive() {
        InterceptUrl url = new InterceptUrl("/test/*/path/**", "ROLE_USER");

        String[] tests = new String[] {
                "/test/3/path/",
                "/test/3/path",
                "/test/testString/path/andSomethingElse",
                "/test/other/path/other_stuff/in/path"
        };

        for (String test : tests) {
            assert url.matches(test) : "Failed for " + test;
        }
    }



}
