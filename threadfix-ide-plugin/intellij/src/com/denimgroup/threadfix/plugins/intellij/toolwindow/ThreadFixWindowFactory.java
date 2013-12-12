package com.denimgroup.threadfix.plugins.intellij.toolwindow;

import com.denimgroup.threadfix.plugins.intellij.markers.WorkspaceUtils;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarker;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import com.intellij.ui.table.JBTable;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

/**
 * Created by mac on 12/12/13.
 */
public class ThreadFixWindowFactory implements ToolWindowFactory {

    ToolWindow myToolWindow = null;
    private JPanel myToolWindowContent;
    private JTable vulnsTable;

    static VulnerabilitiesTableModel tableModel = null;

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

        final VulnerabilitiesTableModel model = getTableModel();

        vulnsTable.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

                if (e.getClickCount() == 2 && !e.isConsumed()) {
                    System.out.println("DID IT!!!");

                    final JTable target = (JTable) e.getSource();
                    final int row    = target.getSelectedRow();
                    final int column = target.getSelectedColumn();

                    System.out.println("Got (" + row + ", " + column + ")");

                    model.doAction(row, column);

                    e.consume();
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {

            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });
        //vulnsTable.get
    }

    public static class VulnerabilitiesTableModel extends DefaultTableModel {

        static String[][] initialObjects = new String[][] { VulnerabilityMarker.getHeaders() };
        static String[] headers = VulnerabilityMarker.getHeaders();
        private VirtualFile[] files;

        private Project project = null;

        public void setProject(Project project) {
            this.project = project;
        }

        // TODO make clickable urls and stuff like that
        public void doAction(int cellRow, int cellColumn) {

            VirtualFile file = getVirtualFileAt(cellRow);

            Document document = FileDocumentManager.getInstance().getDocument(file);

            int lineNumber = Integer.valueOf(getValueAt(cellRow, VulnerabilityMarker.LINE_NUMBER_INDEX).toString());

            int offset = document.getLineStartOffset(lineNumber);

            WorkspaceUtils.openFile(project, file, offset);
        }

        public VirtualFile getVirtualFileAt(int row) {
            return files[row];
        }

        public void setVirtualFileAt(int row, VirtualFile file) {
            files[row] = file;
        }

        public void initVirtualFiles(int size) {
            files = new VirtualFile[size];
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return false;
        }

        public VulnerabilitiesTableModel() {
            super(initialObjects, headers);
            clear();
        }

        public void clear() {
            setRowCount(0);
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }
    }

}
