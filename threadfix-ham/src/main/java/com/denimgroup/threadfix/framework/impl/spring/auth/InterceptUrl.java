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
package com.denimgroup.threadfix.framework.impl.spring.auth;

import org.xml.sax.Attributes;

/**
 * Created by mcollins on 3/31/15.
 */
public class InterceptUrl {

    private final String pattern, role;

    public InterceptUrl(Attributes attributes) {
        pattern = attributes.getValue("pattern");
        role    = attributes.getValue("access");
    }

    public boolean matches(String url) {
        // TODO implement this

        return false;
    }

    @Override
    public String toString() {
        return pattern + " -> " + role;
    }
}
