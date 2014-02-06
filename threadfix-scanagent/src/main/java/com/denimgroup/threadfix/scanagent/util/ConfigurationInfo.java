package com.denimgroup.threadfix.scanagent.util;

import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;

public class ConfigurationInfo {

    private static Logger LOG = Logger.getLogger(ConfigurationInfo.class);

    /**
     * Get some data about the local agent configuration to help identify this
     * agent to the server. This isn't intended to be a secure unique identifier,
     * but is instead intended to provide some debugging support. This is then
     * cached so it can be sent along with requests to the ThreadFix server.
     */
    public static String getAgentConfig() {
        StringBuilder sb = new StringBuilder();

        String prefix;

        String[] properties = {
                "os.arch", "os.name", "os.version", "user.name", "user.dir",
                "user.home", "java.home", "java.vendor", "java.version"
        };

        //	Grab some OS/user/Java environment properties
        for (String property : properties) {
            sb.append(makeSystemPropertyString(property));
        }

        //	Pull some info about the network configuration of the scan agent
        Enumeration<NetworkInterface> nets = null;
        try {
            nets = NetworkInterface.getNetworkInterfaces();

            for (NetworkInterface netint : Collections.list(nets)) {
                sb.append("NETWORK:");
                sb.append(netint.getDisplayName());
                sb.append("=");

                prefix = "";
                for(java.net.InterfaceAddress address : netint.getInterfaceAddresses()) {
                    InetAddress inetAddress = address.getAddress();
                    sb.append(prefix);
                    sb.append(inetAddress.getHostAddress());
                    prefix = ",";
                }
                sb.append("\n");
            }
        } catch (SocketException e) {
            String message = "Problems checking network interfaces when trying to gather agent config: " + e.getMessage();
            LOG.warn(message, e);
            sb.append("\nERROR=");
            sb.append(message);
        }

        String agentConfig = sb.toString();

        LOG.debug("About to dump agent config");
        LOG.debug(agentConfig);

        return agentConfig;
    }


    /**
     * Grab a system property and return a string in the format:
     * key=value\n
     * (note the trailing newline)
     *
     */
    @NotNull
    private static String makeSystemPropertyString(@NotNull String propertyName) {
        return propertyName + "=" + System.getProperty(propertyName) + "\n";
    }

}
