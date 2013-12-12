package com.denimgroup.threadfix.plugins.intellij.toolwindow;

import com.denimgroup.threadfix.plugins.intellij.markers.WorkspaceUtils;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarker;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;

import javax.swing.table.DefaultTableModel;

/**
 * Created by mac on 12/12/13.
 */
public class VulnerabilitiesTableModel extends DefaultTableModel {

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

        String stringLineNumber = getValueAt(cellRow, VulnerabilityMarker.LINE_NUMBER_INDEX).toString();

        int lineNumber = 0;

        if (stringLineNumber.matches("^[0-9]+$")) {
            try {
                lineNumber = Integer.valueOf(getValueAt(cellRow, VulnerabilityMarker.LINE_NUMBER_INDEX).toString());
            } catch (NumberFormatException e) {
                System.out.println("Got NumberFormatException for String " + stringLineNumber);
            }
        } else {
            System.out.println("Line number was not numeric.");
        }

        // IntelliJ reports a possible NPE here but I can't see why. It shouldn't be an autoboxing error as
        // both the parameter and return value are primitives.
        int offset = document.getLineStartOffset(lineNumber);

        if (offset < 0) {
            offset = 0;
        }
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