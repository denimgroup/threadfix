package com.denimgroup.threadfix.plugins.intellij.toolwindow;

import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

/**
 * Created by mac on 12/12/13.
 */
public class FileOpenerMouseListener implements MouseListener {

    final VulnerabilitiesTableModel model;

    public FileOpenerMouseListener(VulnerabilitiesTableModel tableModel) {
        this.model = tableModel;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        if (e.getClickCount() == 2 && !e.isConsumed()) {

            final JTable target = (JTable) e.getSource();
            final int row    = target.getSelectedRow();
            final int column = target.getSelectedColumn();

            System.out.println("Got (" + row + ", " + column + ")");

            model.doAction(row, column);

            e.consume();
        }
    }

    @Override
    public void mousePressed(MouseEvent e) {}

    @Override
    public void mouseReleased(MouseEvent e) {}

    @Override
    public void mouseEntered(MouseEvent e) {}

    @Override
    public void mouseExited(MouseEvent e) {}
}
