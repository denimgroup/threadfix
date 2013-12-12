package com.denimgroup.threadfix.plugins.intellij.action;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.PlatformDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindowManager;

/**
 * Created by mac on 12/12/13.
 */
public class ShowAction extends AnAction {
    public void actionPerformed(AnActionEvent e) {
        Project project = e.getData(PlatformDataKeys.PROJECT);

        ToolWindowManager manager = ToolWindowManager.getInstance(project);

        manager.getToolWindow("ThreadFix").show(null);
    }
}
