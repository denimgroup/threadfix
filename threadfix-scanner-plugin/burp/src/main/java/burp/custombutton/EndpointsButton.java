package burp.custombutton;

import burp.IBurpExtenderCallbacks;
import burp.dialog.ConfigurationDialogs;
import burp.dialog.UrlDialog;
import burp.extention.RestUtils;
import com.denimgroup.threadfix.data.interfaces.Endpoint;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 12/30/13
 * Time: 2:28 PM
 * To change this template use File | Settings | File Templates.
 */
public class EndpointsButton extends JButton {

    public static final String GENERIC_INT_SEGMENT = "\\{id\\}";

    public EndpointsButton(final Component view, final IBurpExtenderCallbacks callbacks) {
        setText("Import Endpoints");

        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                boolean configured = ConfigurationDialogs.show(view);
                boolean completed = false;
                java.util.List<String> nodes = new ArrayList<>();

                if (configured) {
                    Endpoint.Info[] endpoints = RestUtils.getEndpoints();

                    if (endpoints.length == 0) {
                        JOptionPane.showMessageDialog(view, "Failed to retrieve endpoints from ThreadFix. Check your key and url.",
                                "Warning", JOptionPane.WARNING_MESSAGE);
                    } else {
                        for (Endpoint.Info endpoint : endpoints) {
                            if (endpoint != null) {
                                String endpointPath = endpoint.getUrlPath();
                                if(endpointPath.startsWith("/")){
                                    endpointPath = endpointPath.substring(1);
                                }
                                endpointPath = endpointPath.replaceAll(GENERIC_INT_SEGMENT, "1");
                                nodes.add(endpointPath);

                                for (String parameter : endpoint.getParameters()) {
                                    nodes.add(endpointPath + "?" + parameter + "=true");
                                }
                            }
                        }

                        String url = UrlDialog.show(view);

                        if (url != null) { // cancel not pressed
                            try {
                                if(!url.substring(url.length()-1).equals("/")){
                                    url = url+"/";
                                }
                                for (String node: nodes) {
                                    callbacks.sendToSpider(new URL(url + node));
                                }
                                completed = true;
                            } catch (MalformedURLException e1) {
                                JOptionPane.showMessageDialog(view, "Invalid URL.",
                                        "Warning", JOptionPane.WARNING_MESSAGE);
                            }
                        }
                    }
                }

                if (completed) {
                    JOptionPane.showMessageDialog(view, "The endpoints were successfully imported from ThreadFix.");
                }
            }
        });
    }
}
