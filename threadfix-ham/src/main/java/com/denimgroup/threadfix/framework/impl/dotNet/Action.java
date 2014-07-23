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

import javax.annotation.Nonnull;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by mac on 6/26/14.
 */
class Action {
    @Nonnull
    String      name;
    @Nonnull
    Set<String> attributes;
    @Nonnull
    Integer     lineNumber;
    @Nonnull
    Set<String> parameters = new HashSet<>();

    String getMethod() {
        return attributes.contains("HttpPost") ?
                "POST" : "GET";
    }

    static Action action(@Nonnull String name, @Nonnull Set<String> attributes,
                         @Nonnull Integer lineNumber, @Nonnull Set<String> parameters) {
        Action action = new Action();
        action.name = name;
        action.attributes = attributes;
        action.lineNumber = lineNumber;
        action.parameters = parameters;
        return action;
    }

    @Override
    public String toString() {
        return name + ": " + getMethod() + parameters;
    }

}

