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
import java.util.*;

import static com.denimgroup.threadfix.framework.impl.dotNet.Action.action;

/**
 * Created by mac on 6/11/14.
 */
public class DotNetControllerMappings {

    private String              controllerName = null;
    private Map<String, Action> actions        = new HashMap<>();

    public String getFilePath() {
        return filePath;
    }

    private final String filePath;


    public void setControllerName(@Nonnull String controllerName) {
        assert this.controllerName == null : "These mappings already have a controller name.";
        this.controllerName = controllerName;
    }

    public String getControllerName() {
        assert controllerName != null : "You have attempted to access the controller name without setting it.";
        return controllerName;
    }

    public boolean hasValidMappings() {
        return controllerName != null && !actions.isEmpty();
    }

    public void addAction(@Nonnull String action, @Nonnull Set<String> attributes, @Nonnull Integer lineNumber) {
        actions.put(action, action(action, attributes, lineNumber));
    }

    @Nonnull
    public List<Action> getActions() {
        return new ArrayList<>(actions.values());
    }

    public DotNetControllerMappings(String filePath) {
        this.filePath = filePath;
    }

}
