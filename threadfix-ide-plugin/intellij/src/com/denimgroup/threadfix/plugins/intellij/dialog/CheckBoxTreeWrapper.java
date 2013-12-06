package com.denimgroup.threadfix.plugins.intellij.dialog;

import com.intellij.ui.CheckboxTree;
import com.intellij.ui.CheckedTreeNode;
import com.intellij.ui.SimpleTextAttributes;
import com.intellij.ui.components.JBScrollPane;

import javax.swing.*;
import javax.swing.tree.TreeNode;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashSet;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/5/13
 * Time: 10:36 AM
 * To change this template use File | Settings | File Templates.
 */
class CheckBoxTreeWrapper {

    public static class Result {
        boolean success = false;
        Set<String> checkedKeys = new HashSet<String>();
    }

    private final Result result = new Result();
    private final JDialog topPanel;
    private final CheckboxTree tree;

    private CheckBoxTreeWrapper(CheckedTreeNode rootNode) {
        topPanel = new JDialog();
        topPanel.setTitle("Pick ThreadFix Applications");

        tree = new CheckboxTree(new AppRenderer(), rootNode);
        JScrollPane jScrollPane = new JBScrollPane(tree);
        jScrollPane.setPreferredSize(new Dimension(600, 400));
        topPanel.getContentPane().add(jScrollPane, BorderLayout.CENTER);

        JPanel buttonPanel = getButtonsPanel();
        topPanel.getContentPane().add(buttonPanel, BorderLayout.SOUTH);

        topPanel.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        topPanel.setSize(new Dimension(600,800));
        topPanel.setLocationRelativeTo(null);
        topPanel.pack();
    }

    private static class AppRenderer extends CheckboxTree.CheckboxTreeCellRenderer {
        private AppRenderer() {
            super(true, false);
        }

        @Override
        public void customizeRenderer(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            if (value instanceof ThreadFixAppNode) {
                final ThreadFixAppNode node = (ThreadFixAppNode)value;
                getTextRenderer().append(node.getName(), SimpleTextAttributes.REGULAR_ATTRIBUTES);
            }
        }
    }

    private JPanel getButtonsPanel() {
        JPanel buttonPanel = new JPanel();
        final JButton okButton = new JButton("OK");

        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                result.success = true;
                result.checkedKeys = collectValues();
                topPanel.dispose();
            }
        });

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                result.success = false;
                topPanel.dispose();
            }
        });

        buttonPanel.add(cancelButton);
        buttonPanel.add(okButton);

        topPanel.getRootPane().setDefaultButton(okButton);

        buttonPanel.setSize(new Dimension(600, 100));

        return buttonPanel;
    }

    Set<String> collectValues() {

        Object treeRoot = tree.getModel().getRoot();
        final Set<String> returnSet =  new HashSet<String>();

        if (treeRoot instanceof CheckedTreeNode) {
            new Object() {
                public void collect(CheckedTreeNode node) {
                    if (node.isLeaf() && node.isChecked() && node instanceof ThreadFixAppNode) {
                        final ThreadFixAppNode value = (ThreadFixAppNode)node;
                        returnSet.add(value.getId());
                    } else {
                        for (int i = 0; i < node.getChildCount(); i++) {
                            final TreeNode child = node.getChildAt(i);
                            if (child instanceof CheckedTreeNode) {
                                collect((CheckedTreeNode)child);
                            }
                        }
                    }
                }
            }.collect((CheckedTreeNode)treeRoot);
        }

        return returnSet;
    }

    Result showAndGetResult() {
        topPanel.setModal(true);
        topPanel.setVisible(true);
        return result;
    }

    public static void main(String[] args) {
        Result result = run(createRootNode());

        System.out.println(result.checkedKeys);

    }

    private static CheckedTreeNode createRootNode() {
        ThreadFixAppNode rootNode = new ThreadFixAppNode("foo", "test");

        for (String key : new String[] {"a", "b", "c"}) {
            ThreadFixAppNode checkedTreeNode = new ThreadFixAppNode(key, key);

            rootNode.add(checkedTreeNode);

            for (String inner : new String[] {"test1", "test2", "test3"}) {
                checkedTreeNode.add(new ThreadFixAppNode(inner, inner));
            }
        }

        return rootNode;
    }

    public static Result run(CheckedTreeNode rootNode) {
        CheckBoxTreeWrapper dialog = new CheckBoxTreeWrapper(rootNode);

        Result result = dialog.showAndGetResult();

        System.out.println("Result was " + result.success);

        return result;
    }

}
