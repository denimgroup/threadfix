package burp.dialog;

import burp.extention.BurpPropertiesManager;

import javax.swing.*;
import java.awt.*;

public class ParametersDialog {

    public static boolean show(Component view) {
        JTextField urlField = new JTextField(40);
        urlField.setText(BurpPropertiesManager.getUrlStatic());
        JTextField keyField = new JTextField(40);
        keyField.setText(BurpPropertiesManager.getKeyStatic());

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

        ImageIcon icon = new ImageIcon(attempt);

        int result = JOptionPane.showConfirmDialog(view,
                myPanel,
                "Please enter the ThreadFix URL and API Key values",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                icon);
        if (result == JOptionPane.OK_OPTION) {
            BurpPropertiesManager.setKeyAndUrl(keyField.getText(), urlField.getText());
            return true;
        } else {
            return false;
        }
    }

}
