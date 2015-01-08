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
package com.denimgroup.threadfix.plugins.intellij.toolwindow;

import com.denimgroup.threadfix.plugins.intellij.markers.MarkerUtils;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import com.intellij.ui.table.JBTable;

import javax.swing.*;
import javax.swing.table.TableColumn;

public class ThreadFixWindowFactory implements ToolWindowFactory {

    private ToolWindow myToolWindow = null;
    private JPanel myToolWindowContent;
    private JTable vulnsTable;

    private static final int PREFERRED_ID_COL_LENGTH = 90;

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

        setIdColumnLength(MarkerUtils.CWE_ID_INDEX);
        setIdColumnLength(MarkerUtils.LINE_NUMBER_INDEX);

        getTableModel().fireTableDataChanged();
    }

    private void setIdColumnLength(int index) {
        TableColumn column = vulnsTable.getColumnModel().getColumn(index);
        column.setMaxWidth(PREFERRED_ID_COL_LENGTH);
        column.setMinWidth(PREFERRED_ID_COL_LENGTH);
    }
}
