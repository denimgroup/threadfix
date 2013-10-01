package org.zaproxy.zap.extension.threadfix;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ResourceBundle;

import javax.swing.JMenuItem;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

public class ThreadFixExtension extends ExtensionAdaptor {

    private JMenuItem importAction = null, endpointsAction = null;
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
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
       logger.info("Hook");
        super.hook(extensionHook);

        if (getView() != null) {
            // Register our top menu item, as long as we're not running as a daemon
            // Use one of the other methods to add to a different menu list
            extensionHook.getHookMenu().addToolsMenuItem(getImportAction());
            extensionHook.getHookMenu().addToolsMenuItem(getEndpointsAction());
        }

    }

    private JMenuItem getImportAction() {
       logger.info("Getting menu");
        if (importAction == null) {
            importAction = new ImportAction(getView(), getModel());
        }
        return importAction;
    }

    private JMenuItem getEndpointsAction() {
       logger.info("Getting menu");
        if (endpointsAction == null) {
            endpointsAction = new EndpointsAction(getView(), getModel());
        }
        return endpointsAction;
    }

    public String getMessageString(String key) {
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