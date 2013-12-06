package com.denimgroup.threadfix.plugins.intellij.dialog;

import com.denimgroup.threadfix.plugins.intellij.properties.PropertiesManager;
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
public class ApplicationsDialog {

    final ApplicationsMap applicationsMap;
    final Set<String> currentIds;

    private ApplicationsDialog(){
        this.applicationsMap = ThreadFixApplicationService.getApplications();
        this.currentIds = PropertiesManager.getApplicationIds();
    }

    public static Set<String> getApplications() {
        return new ApplicationsDialog().run().checkedKeys;
    }

    public CheckBoxTreeWrapper.Result run() {
        return CheckBoxTreeWrapper.run(createRootNode());
    }

    private CheckedTreeNode createRootNode() {
        CheckedTreeNode rootNode = new ThreadFixAppNode("root", "rootnode");

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
