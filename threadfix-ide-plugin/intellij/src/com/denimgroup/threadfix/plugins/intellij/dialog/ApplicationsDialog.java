package com.denimgroup.threadfix.plugins.intellij.dialog;

import com.denimgroup.threadfix.plugins.intellij.rest.ApplicationsMap;
import com.denimgroup.threadfix.plugins.intellij.rest.ThreadFixApplicationService;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.ui.CheckedTreeNode;

import java.util.*;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/5/13
 * Time: 9:35 AM
 * To change this template use File | Settings | File Templates.
 */
public class ApplicationsDialog {

    public static Set<String> getApplications(AnActionEvent e) {
        ApplicationsMap applicationsMap = ThreadFixApplicationService.getApplications();

        CheckBoxTreeWrapper.Result result = CheckBoxTreeWrapper.run(createRootNode(applicationsMap));

        return result.checkedKeys;
    }

    private static CheckedTreeNode createRootNode(ApplicationsMap applicationsMap) {
        CheckedTreeNode rootNode = new ThreadFixAppNode("root", "rootnode");

        Map<String, CheckedTreeNode> teamNodesMap = new HashMap<String, CheckedTreeNode>();

        for (String team : applicationsMap.getTeams()) {
            teamNodesMap.put(team, constructNode(rootNode, team));

            for (String app : applicationsMap.getApps(team)) {
                String id = applicationsMap.getId(team, app);
                constructNode(teamNodesMap.get(team), app, id);
            }
        }

        return rootNode;
    }

    private static CheckedTreeNode constructNode(CheckedTreeNode parent, String key) {
        CheckedTreeNode node = new ThreadFixAppNode(key, null);
        parent.add(node);
        return node;
    }

    private static CheckedTreeNode constructNode(CheckedTreeNode parent, String key, String id) {
        ThreadFixAppNode node = new ThreadFixAppNode(key, id);
        parent.add(node);
        return node;
    }


}
