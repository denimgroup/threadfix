package org.zaproxy.zap.extension.threadfix;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;

import javax.swing.*;
import java.awt.*;

public class UrlDialog {

    private static final Logger logger = Logger.getLogger(UrlDialog.class);

    public static String show(ViewDelegate view) {
        logger.info("Attempting to show dialog.");
        JTextField urlField = new JTextField(40);
        urlField.setText(ThreadFixPropertiesManager.getUrl());

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

        String attempt = UrlDialog.class.getProtectionDomain().getCodeSource().getLocation().getFile() + "/dg-icon.png";

        logger.info("Trying " + attempt);

        ImageIcon icon = new ImageIcon(attempt);

        int result = JOptionPane.showConfirmDialog(view.getMainFrame(),
                myPanel,
                "Please enter the ThreadFix URL",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                icon);
        if (result == JOptionPane.OK_OPTION) {
            logger.info("Got url, returning.");
            return urlField.getText();
        } else {
            logger.info("Cancel pressed.");
            return "http://localhost";
        }
    }

}
