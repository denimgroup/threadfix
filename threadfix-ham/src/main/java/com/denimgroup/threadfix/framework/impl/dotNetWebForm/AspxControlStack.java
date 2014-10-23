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

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by mac on 10/20/14.
 */
class AspxControlStack {

    private static final SanitizedLogger LOG = new SanitizedLogger(AspxControlStack.class);

    Map<String, Integer> idMap    = newMap(); // this helps us generate
    List<AspxControl>    controls = list(new AspxControl("RootElement", generateIdFromCurrentStack(0)));

    void add(AspxControl control) {
        assert control.name != null : "Control's name was null.";

        int startingId = control.name.contains("Field") ? 1 : 0;

        AspxControl finalControl =
                control.id == null ?
                        new AspxControl(control.name, generateIdFromCurrentStack(startingId)) :
                        control;

        controls.add(finalControl);

        LOG.debug("Adding " + control.name + " with id " + control.id + ". Base is now " + getCurrentString());
    }

    private String generateIdFromCurrentStack(int numberToStartAt) {
        String base = getCurrentString();

        if (!idMap.containsKey(base)) {
            idMap.put(base, numberToStartAt);
        }

        Integer result = idMap.get(base);

        idMap.put(base, idMap.get(base) + 1);

        return result > 9 ? "ctl" + result : "ctl0" + result;
    }

    String generateCurrentParamName() {
        return getCurrentString();
    }

    private String getCurrentString() {
        StringBuilder builder = new StringBuilder();

        if (controls != null) { // null during initialization
            for (AspxControl aspxControl : controls) {
                builder.append(aspxControl.id).append("$");
            }
        }

        if (builder.length() > 0) {
            builder.setLength(builder.length() -1);
        }

        return builder.toString();
    }

    void removeLast() {
        int lastIndex = controls.size() - 1;
        AspxControl removedControl = controls.remove(lastIndex);

        LOG.debug("Removing " + removedControl.name + " with id " + removedControl.id + ". Base is now " +  getCurrentString());
    }

}
