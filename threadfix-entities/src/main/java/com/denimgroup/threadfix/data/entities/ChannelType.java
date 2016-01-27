////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.data.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

@Entity
@Table(name = "ChannelType")
public class ChannelType extends BaseEntity {

	private static final long serialVersionUID = 1665587716223810215L;
	
	// This set is used to hold the channel types that should include their native IDs in the vuln description.
	// Any useful native IDs should be included here, but not ones that we generate ourselves.
	public final static Set<String> NATIVE_ID_SCANNERS = set(
			ScannerType.CAT_NET.getDisplayName(),
			ScannerType.FORTIFY.getDisplayName(),
			ScannerType.SENTINEL.getDisplayName(),
			ScannerType.VERACODE.getDisplayName());
	
	public static final Set<String> DYNAMIC_TYPES = set(
			ScannerType.ACUNETIX_WVS.getDisplayName(),
			ScannerType.APPSCAN_ENTERPRISE.getDisplayName(),
			ScannerType.ARACHNI.getDisplayName(),
			ScannerType.BURPSUITE.getDisplayName(),
			ScannerType.NESSUS.getDisplayName(),
			ScannerType.NETSPARKER.getDisplayName(),
			ScannerType.APP_SPIDER.getDisplayName(),
			ScannerType.SKIPFISH.getDisplayName(),
			ScannerType.W3AF.getDisplayName(),
			ScannerType.WEBINSPECT.getDisplayName(),
			ScannerType.ZAPROXY.getDisplayName(),
			ScannerType.QUALYSGUARD_WAS.getDisplayName(),
			ScannerType.APPSCAN_DYNAMIC.getDisplayName());
	
	public static final Set<String> STATIC_TYPES = set(
			ScannerType.APPSCAN_SOURCE.getDisplayName(),
			ScannerType.FINDBUGS.getDisplayName(),
			ScannerType.FORTIFY.getDisplayName(),
			ScannerType.VERACODE.getDisplayName(),
			ScannerType.CAT_NET.getDisplayName(),
			ScannerType.BRAKEMAN.getDisplayName(),
            ScannerType.PMD.getDisplayName(),
            ScannerType.CLANG.getDisplayName(),
			ScannerType.CPPCHECK.getDisplayName());

	public static final List<String> MIXED_TYPES = Arrays.asList(ScannerType.SENTINEL.getDisplayName());
	public static final String DYNAMIC="Dynamic", STATIC="Static", MIXED="Mixed";

	private List<ApplicationChannel> applicationChannels;
	private List<ChannelSeverity> channelSeverities;
	private List<ChannelVulnerability> channelVulnerabilities;
	private List<RemoteProviderType> remoteProviderTypes;
	
	private String name;
	private String url;
	private String version;
	private String exportInfo;

	@Column(length = 50, nullable = false)
    @JsonView(Object.class)
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

    @JsonIgnore
	@Column(length = 1024, nullable = true)
	public String getExportInfo() {
		return exportInfo;
	}

	public void setExportInfo(String exportInfo) {
		this.exportInfo = exportInfo;
	}

	@OneToMany(mappedBy = "channelType")
	@JsonIgnore
	public List<ChannelVulnerability> getChannelVulnerabilities() {
		return channelVulnerabilities;
	}

	public void setChannelVulnerabilities(List<ChannelVulnerability> channelVulnerabilities) {
		this.channelVulnerabilities = channelVulnerabilities;
	}

	@OneToMany(mappedBy = "channelType")
	@JsonIgnore
	public List<ChannelSeverity> getChannelSeverities() {
		return channelSeverities;
	}

	public void setChannelSeverities(List<ChannelSeverity> channelSeverities) {
		this.channelSeverities = channelSeverities;
	}

	@OneToMany(mappedBy = "channelType")
	@JsonIgnore
	public List<ApplicationChannel> getChannels() {
		return applicationChannels;
	}

	public void setChannels(List<ApplicationChannel> applicationChannels) {
		this.applicationChannels = applicationChannels;
	}
	
	@OneToMany(mappedBy = "channelType")
	@JsonIgnore
	public List<RemoteProviderType> getRemoteProviderTypes() {
		return remoteProviderTypes;
	}

	public void setRemoteProviderTypes(List<RemoteProviderType> remoteProviderTypes) {
		this.remoteProviderTypes = remoteProviderTypes;
	}

	@Transient
	@JsonView(Object.class)
	public String getMappingFilterName() {
		String mappingFilterName = name;

		if (mappingFilterName.equals(ScannerType.APPSCAN_DYNAMIC.getDisplayName())) {
			mappingFilterName = mappingFilterName + "/Enterprise";
		}

		if (mappingFilterName.equals(ScannerType.MANUAL.getDisplayName())) {
			mappingFilterName += "/" + ScannerType.DEPENDENCY_CHECK.getDisplayName() + "/" + ScannerType.SSVL.getDisplayName();
		}

		return mappingFilterName;
	}

}
