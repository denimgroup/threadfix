////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.scanagent.configuration;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.scanagent.util.ScanAgentPropertiesManager;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class Scanner {

    private static Logger log = Logger.getLogger(Scanner.class);

    @NotNull
	private String name;
	@Nullable
    private String version;
	@NotNull
    private String homeDir;
    @Nullable
    private String host;
    private int port;
	
	public Scanner() {}
	
	public Scanner(@NotNull String name, @Nullable String version,
                   @NotNull String homeDir, @Nullable String host, int port) {
		this.name = name;
		this.version = version;
		this.homeDir = homeDir;
		this.host = host;
		this.port = port;
	}

	@NotNull
    public String getName() {
		return(name);
	}
	
	@Nullable
    public String getVersion() {
		return(version);
	}
	
	@NotNull
    public String getHomeDir() {
		return homeDir;
	}

	public void setHomeDir(@NotNull String homeDir) {
		this.homeDir = homeDir;
	}

	@Nullable
    public String getHost() {
		return host;
	}

	public void setHost(@Nullable String host) {
		this.host = host;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public void setName(@NotNull String name) {
		this.name = name;
	}

	public void setVersion(@Nullable String version) {
		this.version = version;
	}

	@NotNull
    @Override
	public String toString() {
		return "Scanner { name = " + name + ", version = " + version + ", home directory = " 
						+ homeDir + ", host = " + host + ", port = " + port + " }";
	}

    public static Scanner getScannerFromConfiguration(ScannerType type) {
        Scanner scanner = null;
        String scanName = ScanAgentPropertiesManager.getFromProperties(type);
        if (scanName != null && !scanName.isEmpty()) {

            scanner = new Scanner();
            scanner.setName(scanName);
            scanner.setVersion(ScanAgentPropertiesManager.readProperty(
                    type.getShortName() + ".scanVersion"));
            scanner.setHomeDir(ScanAgentPropertiesManager.readProperty(
                    type.getShortName() + ".scanExecutablePath"));
            scanner.setHost(ScanAgentPropertiesManager.readProperty(
                    type.getShortName() + ".scanHost"));

            String portString = ScanAgentPropertiesManager.readProperty(
                    type.getShortName() + ".scanPort");

            if (portString != null && portString.matches("^[0-9]+$")) {
                scanner.setPort(Integer.valueOf(portString));
            } else {
                log.info("No valid port configured for " + type.getShortName());
            }
        }

        return scanner;
    }

    public void saveInformation() {
        ScannerType type = ScannerType.getScannerType(getName());
        String name = type.getShortName();

        ScanAgentPropertiesManager.writeProperty(name + ".scanName", type.getFullName());
        ScanAgentPropertiesManager.writeProperty(name + ".scanVersion", getVersion());
        ScanAgentPropertiesManager.writeProperty(name + ".scanExecutablePath", getHomeDir());
        ScanAgentPropertiesManager.writeProperty(name + ".scanHost", getHost());
        ScanAgentPropertiesManager.writeProperty(name + ".scanPort", String.valueOf(getPort()));
    }
}
