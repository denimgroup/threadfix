////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "ChannelType")
public class ChannelType extends BaseEntity {

	private static final long serialVersionUID = 1665587716223810215L;
	// Types of channels
	public static final String CAT_NET = "Microsoft CAT.NET";
	public static final String APPSCAN_DYNAMIC = "IBM Rational AppScan";
	public static final String NETSPARKER = "Mavituna Security Netsparker";
	public static final String SENTINEL = "WhiteHat Sentinel";
	public static final String MANUAL = "Manual";
	public static final String SKIPFISH = "Skipfish";
	public static final String W3AF = "w3af";
	public static final String VERACODE = "Veracode";
	public static final String WEBINSPECT = "WebInspect";
	public static final String BURPSUITE = "Burp Suite";
	public static final String FINDBUGS = "FindBugs";
	public static final String ZAPROXY = "OWASP Zed Attack Proxy";
	public static final String FORTIFY = "Fortify 360";
	public static final String NESSUS = "Nessus";
	public static final String ARACHNI = "Arachni";

	private String name;
	private String version;
	private String url;
	
	@NotEmpty(message = "{errors.required}")
	@Size(max = 255, message = "{errors.maxlength} " + 255 + ".")
	private String apiKey;

	private List<ChannelVulnerability> channelVulnerabilities;
	private List<ChannelSeverity> channelSeverities;
	private List<ApplicationChannel> applicationChannels;
	private List<VulnerabilityMapLog> vulnerabilityMapLogs;

	@Column(length = 50, nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = 20, nullable = false)
	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	@Column(length = 255, nullable = true)
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	@Column(length = 255, nullable = true)
	public String getApiKey() {
		return apiKey;
	}

	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}

	@OneToMany(mappedBy = "channelType")
	public List<ChannelVulnerability> getChannelVulnerabilities() {
		return channelVulnerabilities;
	}

	public void setChannelVulnerabilities(List<ChannelVulnerability> channelVulnerabilities) {
		this.channelVulnerabilities = channelVulnerabilities;
	}

	@OneToMany(mappedBy = "channelType")
	public List<ChannelSeverity> getChannelSeverities() {
		return channelSeverities;
	}

	public void setChannelSeverities(List<ChannelSeverity> channelSeverities) {
		this.channelSeverities = channelSeverities;
	}

	@OneToMany(mappedBy = "channelType")
	public List<ApplicationChannel> getChannels() {
		return applicationChannels;
	}

	public void setChannels(List<ApplicationChannel> applicationChannels) {
		this.applicationChannels = applicationChannels;
	}

	@OneToMany(mappedBy = "channelType")
	public List<VulnerabilityMapLog> getVulnerabilityMapLogs() {
		return vulnerabilityMapLogs;
	}

	public void setVulnerabilityMapLogs(List<VulnerabilityMapLog> vulnerabilityMapLogs) {
		this.vulnerabilityMapLogs = vulnerabilityMapLogs;
	}

}
