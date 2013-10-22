package com.denimgroup.threadfix.plugin.zap.dialog;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.threadfix.ThreadFixPropertiesManager;

public class ParametersDialog {

    private static final Logger logger = Logger.getLogger(ParametersDialog.class);

    public static boolean show(ViewDelegate view) {
        logger.info("Attempting to show dialog.");
        JTextField urlField = new JTextField(40);
        urlField.setText(ThreadFixPropertiesManager.getUrl());
        JTextField keyField = new JTextField(40);
        keyField.setText(ThreadFixPropertiesManager.getKey());

        GridBagLayout experimentLayout = new GridBagLayout();
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        GridBagConstraints textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

        JPanel myPanel = new JPanel();
        myPanel.setLayout(experimentLayout);
        myPanel.add(new JLabel("URL"), labelConstraints);
        myPanel.add(urlField, textBoxConstraints);

        labelConstraints.gridy = 1;
        textBoxConstraints.gridy = 1;

        myPanel.add(new JLabel("API Key"), labelConstraints);
        myPanel.add(keyField, textBoxConstraints);

        String attempt = ParametersDialog.class.getProtectionDomain().getCodeSource().getLocation().getFile() + "/dg-icon.png";

        logger.info("Trying " + attempt);

        ImageIcon icon = new ImageIcon(attempt);

        int result = JOptionPane.showConfirmDialog(view.getMainFrame(),
                myPanel,
                "Please enter the ThreadFix URL and API Key values",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                icon);
        if (result == JOptionPane.OK_OPTION) {
            ThreadFixPropertiesManager.setKeyAndUrl(keyField.getText(), urlField.getText());
            logger.info("Got properties and saved.");
            return true;
        } else {
            logger.info("Cancel pressed.");
            return false;
        }
    }

}
