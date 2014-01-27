package burp.custombutton;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.dialog.ConfigurationDialogs;
import burp.extention.BurpPropertiesManager;
import burp.extention.RestUtils;
import com.denimgroup.threadfix.remote.response.RestResponse;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 12/30/13
 * Time: 2:28 PM
 * To change this template use File | Settings | File Templates.
 */
public class ExportButton extends JButton {

    public ExportButton(final Component view, final IBurpExtenderCallbacks callbacks) {
        setText("Export Scan");
        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                boolean configured = ConfigurationDialogs.show(view);
                if (configured) {
                    File file = generateXml(callbacks);
                    if (file != null && file.exists()) {
                        RestResponse<Object> object = RestUtils.uploadScan(file);
                        if (object.responseCode == 0) {
                            JOptionPane.showMessageDialog(view, "The response code was 0, indicating that the ThreadFix server " +
                                    "was unreachable. Make sure that the server is running and not blocked by the BURP " +
                                    "local proxy.", "Warning", JOptionPane.WARNING_MESSAGE);
                        } else if (object.success) {
                            JOptionPane.showMessageDialog(view, "The scan was uploaded to ThreadFix successfully.");
                        } else {
                            JOptionPane.showMessageDialog(view, "The upload failed. The response code was " +
                                    object.responseCode +
                                    " and the error message was " +
                                    object.message);
                        }
                    } else {
                        // file didn't exist
                        JOptionPane.showMessageDialog(view, "Unable to create scan file.",
                                "Warning", JOptionPane.WARNING_MESSAGE);
                    }
                }
            }
        });
    }

    private File generateXml(IBurpExtenderCallbacks callbacks) {
        File file = new File("burp_threadfix.xml");
        IScanIssue[] issues = callbacks.getScanIssues(BurpPropertiesManager.getTargetUrl());
        callbacks.generateScanReport("XML", issues, file);
        return file;

    }
}
