package com.denimgroup.threadfix.plugins.intellij.toolwindow;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import com.intellij.ui.table.JBTable;

import javax.swing.*;

/**
 * Created by mac on 12/12/13.
 */
public class ThreadFixWindowFactory implements ToolWindowFactory {

    private ToolWindow myToolWindow = null;
    private JPanel myToolWindowContent;
    private JTable vulnsTable;

    private static VulnerabilitiesTableModel tableModel = null;

    public static VulnerabilitiesTableModel getTableModel() {
        if (tableModel == null) {
            tableModel = new VulnerabilitiesTableModel();
        }

        return tableModel;
    }

    @Override
    public void createToolWindowContent(Project project, ToolWindow toolWindow) {
        myToolWindow = toolWindow;
        ContentFactory contentFactory = ContentFactory.SERVICE.getInstance();
        Content content = contentFactory.createContent(myToolWindowContent, "", false);
        toolWindow.getContentManager().addContent(content);
    }

    private void createUIComponents() {
        vulnsTable = new JBTable(getTableModel());
        vulnsTable.addMouseListener(new FileOpenerMouseListener(getTableModel()));
    }
}
