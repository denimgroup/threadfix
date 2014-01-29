package com.denimgroup.threadfix.plugin.zap.action;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.swing.JMenuItem;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.remote.PluginClient;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;

import com.denimgroup.threadfix.plugin.zap.dialog.ConfigurationDialogs;
import com.denimgroup.threadfix.plugin.zap.dialog.UrlDialog;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

public class EndpointsAction extends JMenuItem {

	private static final long serialVersionUID = -3141841416510322529L;

	private static final Logger logger = Logger.getLogger(EndpointsAction.class);
	public static final String GENERIC_INT_SEGMENT = "\\{id\\}";

    private AttackThread attackThread = null;

    public EndpointsAction(final ViewDelegate view, final Model model) {
        logger.info("Initializing ThreadFix endpoint menu item");
        setText("ThreadFix: Import Endpoints");

        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {

                logger.info("About to show dialog.");
                
                boolean configured = ConfigurationDialogs.show(view);
                boolean completed = false;
                
                if (configured) {
	                logger.info("Got application id, about to generate XML and use REST call.");
	
	                Endpoint.Info[] endpoints = new PluginClient(ZapPropertiesManager.INSTANCE)
                            .getEndpoints(ZapPropertiesManager.INSTANCE.getAppId());
	                
	                if (endpoints.length == 0) {
	                	view.showWarningDialog("Failed to retrieve endpoints from ThreadFix. Check your key and url.");
	                } else {
	
	                	logger.info("Got " + endpoints.length + " endpoints.");
	
		                for (Endpoint.Info endpoint : endpoints) {
		                    if (endpoint != null) {

		                    	String urlPath = endpoint.getUrlPath();

		                    	if (urlPath.startsWith("/")) {
		                    		urlPath = urlPath.substring(1);
		                    	}

                                urlPath = urlPath.replaceAll(GENERIC_INT_SEGMENT, "1");

		                    	nodes.add(urlPath);

		                    	Set<String> params = endpoint.getParameters();

                                if (!params.isEmpty()) {
                                    for(String parameter : params){
                                        nodes.add(urlPath + "?" + parameter + "=true");
                                    }
                                }
		                    }
		                }
		                
		                String url = UrlDialog.show(view);
		
		                if (url != null) { // cancel not pressed
			                try {
			                	if(!url.substring(url.length()-1).equals("/")){
			                		url = url+"/";
			                	}
			                    attack(new URL(url));
			                    completed = true;
			                } catch (MalformedURLException e1) {
			                    logger.warn("Bad URL format.");
			                    view.showWarningDialog("Invalid URL.");
			                }
		                }
	                }
                }

                if (completed) {
                	view.showMessageDialog("The endpoints were successfully imported from ThreadFix.");
                }
            }
        });
    }

    public void notifyProgress(AttackThread.Progress progress) {
        logger.info("Status is " + progress);
    }

    public void attack (URL url) {
        logger.info("Starting url " + url);

        if (attackThread != null && attackThread.isAlive()) {
            return;
        }
        attackThread = new AttackThread(this);
        attackThread.setNodes(nodes);
        attackThread.setURL(url);
        attackThread.start();

    }

    List<String> nodes = new ArrayList<>();

}
