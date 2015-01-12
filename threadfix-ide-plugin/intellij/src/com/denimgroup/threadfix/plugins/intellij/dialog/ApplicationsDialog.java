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
package com.denimgroup.threadfix.plugins.intellij.dialog;

import com.denimgroup.threadfix.plugins.intellij.properties.IntelliJPropertiesManager;
import com.denimgroup.threadfix.plugins.intellij.rest.ApplicationsMap;
import com.denimgroup.threadfix.plugins.intellij.rest.ThreadFixApplicationService;
import com.intellij.ui.CheckedTreeNode;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/5/13
 * Time: 9:35 AM
 * To change this template use File | Settings | File Templates.
 */
class ApplicationsDialog {

    private final ApplicationsMap applicationsMap;
    private final Set<String> currentIds;

    private ApplicationsDialog(){
        this.applicationsMap = ThreadFixApplicationService.getApplications();
        this.currentIds = IntelliJPropertiesManager.INSTANCE.getApplicationIds();
    }

    public static Set<String> getApplications() {
        return new ApplicationsDialog().run().checkedKeys;
    }

    CheckBoxTreeWrapper.Result run() {
        return CheckBoxTreeWrapper.run(createRootNode());
    }

    private CheckedTreeNode createRootNode() {
        CheckedTreeNode rootNode = new ThreadFixAppNode("", "");

        Map<String, CheckedTreeNode> teamNodesMap = new HashMap<String, CheckedTreeNode>();

        for (String team : applicationsMap.getTeams()) {
            teamNodesMap.put(team, constructNode(rootNode, team));

            boolean allChecked = true;
            for (String app : applicationsMap.getApps(team)) {
                String id = applicationsMap.getId(team, app);
                constructNode(teamNodesMap.get(team), app, id);
                if (!currentIds.contains(id)) {
                    allChecked = false;
                }
            }

            teamNodesMap.get(team).setChecked(allChecked);
        }

        return rootNode;
    }

    private CheckedTreeNode constructNode(CheckedTreeNode parent, String key) {
        CheckedTreeNode node = new ThreadFixAppNode(key, null);
        parent.add(node);
        return node;
    }

    private CheckedTreeNode constructNode(CheckedTreeNode parent, String key, String id) {
        ThreadFixAppNode node = new ThreadFixAppNode(key, id);
        node.setChecked(currentIds.contains(id));
        parent.add(node);
        return node;
    }


}
