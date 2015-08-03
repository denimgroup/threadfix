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
package com.denimgroup.threadfix.importer.utils;

/**
 * Created by mcollins on 8/3/15.
 */
public class AssertionUtils {

    private AssertionUtils(){}

    public static void compare(Number a, Number b) {
        if (!a.equals(b)) {
            assert false : "Expected " + a + " but got " + b;
        }
    }

    public static void compare(String name, Number a, Number b) {
        if (!a.equals(b)) {
            assert false : "Expected " + a + " " + name + " but got " + b;
        }
    }

    public static void compare(String name, String a, String b) {
        if (a == null) {
            assert b == null : "Expected null but got " + b + " for " + name;
        } else {
            assert a.equals(b) : "Expected " + name + " " + a + " but got " + b;
        }
    }
}
