package org.zaproxy.zap.extension.threadfix;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

import javax.swing.*;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ResourceBundle;

public class ThreadFixExtension extends ExtensionAdaptor {

    private JMenuItem importAction = null;
    private ResourceBundle messages = null;

    private static final Logger logger = Logger.getLogger(ThreadFixExtension.class);

    static {
       logger.info("Loading Class");
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    /**
     *
     */
    public ThreadFixExtension() {
        super();
        logger.info("calling constructor");
        initialize();
        logger.info("No-arg Constructor");
        this.setEnabled(true);
    }

    /**
     * @param name
     */
    public ThreadFixExtension(String name) {
        super(name);
       logger.info("1-arg Constructor");
    }

    /**
     * This method initializes this
     *
     */
    private void initialize() {
       logger.info("Initialize");
        this.setName("ThreadFix");
        // Load extension specific language files - these are held in the extension jar
//        messages = ResourceBundle.getBundle(
//                this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
       logger.info("Hook");
        super.hook(extensionHook);

        if (getView() != null) {
            // Register our top menu item, as long as we're not running as a daemon
            // Use one of the other methods to add to a different menu list
            extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
        }

    }

    private JMenuItem getMenuExample() {
       logger.info("Getting menu");
        if (importAction == null) {
            logger.info("Initializing ThreadFix menu item");
            importAction = new JMenuItem();
            importAction.setText("ThreadFix");

            importAction.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {

                logger.info("About to show dialog.");

                ParametersDialog.show(getView());

                logger.info("Got settings. About to show Application selection.");

                ApplicationDialog.show(getView());

                logger.info("Got application id, about to generate XML and use REST call.");

                File file = ReportGenerator.generateXml(getView(), getModel());

                logger.info("File = " + file);
                logger.info("full path = " + file.getAbsoluteFile());

                logger.info("About to try to upload.");
                int responseCode = RestUtils.uploadScan(file);
                if (responseCode == 0) {
                    getView().showWarningDialog("The response code was 0, indicating that the ThreadFix server " +
                            "was unreachable. Make sure that the server is running and not blocked by the ZAP " +
                            "local proxy.");
                } else if (responseCode == -2) {
                    getView().showWarningDialog("The parameters were not saved correctly.");
                } else if (responseCode != 200) {
                    getView().showWarningDialog("Scan upload failed: the HTTP response code was " + responseCode +
                            " and not 200.");
                } else {
                    getView().showMessageDialog("The scan was uploaded to ThreadFix successfully.");
                }
                }
            });
        }
        return importAction;
    }

    public String getMessageString (String key) {
        return messages.getString(key);
    }
    @Override
    public String getAuthor() {
       logger.info("Getting Author");
        return "Denim Group";
    }

    @Override
    public String getDescription() {
       logger.info("Getting Description");
        return "ThreadFix integration";
    }

    @Override
    public URL getURL() {
       logger.info("Getting URL");
        try {
            return new URL("http://code.google.com/p/threadfix/wiki/ZapPlugin");
        } catch (MalformedURLException e) {
            return null;
        }
    }
}