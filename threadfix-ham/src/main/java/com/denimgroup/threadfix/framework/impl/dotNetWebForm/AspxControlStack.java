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

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 10/20/14.
 */
class AspxControlStack {

    AspxControlStack() {}

    List<AspxControl> controls = list();

    void add(AspxControl control) {
        controls.add(control);

        System.out.println("Adding " + control.name + " with id " + control.id);
    }

    void removeLast() {
        int lastIndex = controls.size() - 1;
        AspxControl removedControl = controls.remove(lastIndex);

        System.out.println("Removing " + removedControl.name + " with id " + removedControl.id);
    }

    String generateNameFor(AspxControl control) {
        StringBuilder builder = new StringBuilder("ctl00$");

        for (AspxControl aspxControl : controls) {
            builder.append(aspxControl.id).append("$");
        }

        return builder.append(control.id).toString();
    }

}
