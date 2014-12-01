////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.views.AllViews;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonView;
import org.hibernate.validator.constraints.NotEmpty;
import org.hibernate.validator.constraints.URL;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.*;

@Entity
@Table(name = "Application")
public class Application extends AuditableEntity {

	private static final long serialVersionUID = 1175222046579045669L;
    private static final SanitizedLogger log = new SanitizedLogger(Application.class);
	
	public static final String TEMP_PASSWORD = "this is not the password";
	private List<AccessControlApplicationMap> accessControlApplicationMaps;
	private List<ScanQueueTask> scanQueueTasks;
    private List<ScheduledScan> scheduledScans;

	public static final int 
		NAME_LENGTH = 60,
		URL_LENGTH = 255,
		ENUM_LENGTH = 50;
	
	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;
	
	String frameworkType = FrameworkType.DETECT.toString(),
            sourceCodeAccessLevel = SourceCodeAccessLevel.DETECT.toString(),
            repositoryFolder;

    @URL(message = "{errors.url}")
    @Size(min = 0, max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
    private  String repositoryUrl;

    @Size(max = 80, message = "{errors.maxlength} 80.")
    private String repositoryBranch, repositoryDBBranch;

    @Size(max = 80, message = "{errors.maxlength} 80.")
    private String repositoryUserName;

    @Size(max = 80, message = "{errors.maxlength} 80.")
    private String repositoryPassword;

    @Size(max = 1024, message = "{errors.maxlength} 1024.")
    private String repositoryEncryptedPassword;

    @Size(max = 1024, message = "{errors.maxlength} 1024.")
    private String repositoryEncryptedUserName;

	@URL(message = "{errors.url}")
	@Size(min = 0, max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
	private String url;
	
	@Size(min = 0, max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
	private String uniqueId;
	
	@Size(max = 255, message = "{errors.maxlength} 255.")
	private String projectRoot;
	@Size(max = 255, message = "{errors.maxlength} 255.")
	private String rootPath;

	private Organization organization;
	private Waf waf;
	private ApplicationCriticality applicationCriticality;
	
	@Size(max = 50, message = "{errors.maxlength} 50.")
	private String projectName;
	
	@Size(max = 25, message = "{errors.maxlength} 25.")
	private String projectId;
	
	@Size(max = 50, message = "{errors.maxlength} 50.")
	private String component;
	private DefectTracker defectTracker;
	
	@Size(max = 80, message = "{errors.maxlength} 80.")
	private String userName;
	
	@Size(max = 80, message = "{errors.maxlength} 80.")
	private String password;

	@Size(max = 1024, message = "{errors.maxlength} 1024.")
	private String encryptedPassword;
	
	@Size(max = 1024, message = "{errors.maxlength} 1024.")
	private String encryptedUserName;

    @Size(max = 80, message = "{errors.maxlength} 80.")
    private String obscuredPassword;

    @Size(max = 80, message = "{errors.maxlength} 80.")
    private String obscuredUserName;
	
	private List<Defect> defectList;

	private List<ApplicationChannel> channelList;
	private List<Scan> scans;
	private List<Vulnerability> vulnerabilities;
	private List<RemoteProviderApplication> remoteProviderApplications;
	private List<Document> documents;
	private List<VulnerabilityFilter> filters;

	// these are here so we don't generate them more than we need to
	private List<Integer> reportList = null;
	private List<Finding> findingList = null;
	private List<ApplicationChannel> uploadableChannels = null;

    // These are used for caching and will require frequent updates.
    private Integer infoVulnCount = 0, lowVulnCount = 0, mediumVulnCount = 0,
            highVulnCount = 0, criticalVulnCount = 0, totalVulnCount = 0;

    private Boolean skipApplicationMerge = false;

    private List<Tag> tags = new ArrayList<Tag>();

	@Column(length = NAME_LENGTH, nullable = false)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = URL_LENGTH)
    @JsonView(Object.class)
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}
	
	@Column(length = 255)
    @JsonView({AllViews.RestViewApplication2_1.class, AllViews.FormInfo.class, AllViews.TableRow.class})
	public String getUniqueId() {
		return uniqueId;
	}

	public void setUniqueId(String uniqueId) {
		this.uniqueId = uniqueId;
	}

	@Column(length = 50)
	public String getProjectName() {
		return projectName;
	}

	public void setProjectName(String projectName) {
		this.projectName = projectName;
	}

	@Column(length = 25)
	public String getProjectId() {
		return projectId;
	}

	public void setProjectId(String projectId) {
		this.projectId = projectId;
	}

	@Column(length = 50, nullable = true)
	public String getComponent() {
		return component;
	}

	public void setComponent(String component) {
		this.component = component;
	}
	
	@Transient
    @JsonIgnore
	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	@Transient
    @JsonIgnore
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	@Column(length = 1024)
	@JsonIgnore
	public String getEncryptedPassword() {
		return encryptedPassword;
	}

	public void setEncryptedPassword(String encryptedPassword) {
		this.encryptedPassword = encryptedPassword;
	}

	@Column(length = 1024)
	@JsonIgnore
	public String getEncryptedUserName() {
		return encryptedUserName;
	}

	public void setEncryptedUserName(String encryptedUserName) {
		this.encryptedUserName = encryptedUserName;
	}

    @Transient
    @JsonView(AllViews.FormInfo.class)
    public String getObscuredPassword() {
        if(repositoryEncryptedPassword == null || repositoryEncryptedPassword.trim().length() == 0) {
            return "";
        } else {
            return "12345678";
        }
    }

    @Transient
    @JsonView(AllViews.FormInfo.class)
    public String getObscuredUserName() throws IllegalAccessException {
        return repositoryUserName;
    }

	@ManyToOne(cascade = { CascadeType.PERSIST, CascadeType.MERGE })
	@JoinColumn(name = "defectTrackerId")
    @JsonView(AllViews.FormInfo.class)
    public DefectTracker getDefectTracker() {
		return defectTracker;
	}

	public void setDefectTracker(DefectTracker defectTracker) {
		this.defectTracker = defectTracker;
	}

	@OneToMany(mappedBy = "application")
    @JsonIgnore
	public List<Defect> getDefectList() {
		return defectList;
	}

	public void setDefectList(List<Defect> defectList) {
		this.defectList = defectList;
	}

	@ManyToOne
	@JoinColumn(name = "organizationId")
	@JsonIgnore
	public Organization getOrganization() {
		return organization;
	}

	public void setOrganization(Organization organization) {
		this.organization = organization;
	}

	@ManyToOne(cascade = { CascadeType.PERSIST, CascadeType.MERGE })
	@JoinColumn(name = "wafId")
    @JsonIgnore
	public Waf getWaf() {
		return waf;
	}

	public void setWaf(Waf waf) {
		this.waf = waf;
	}

    @Transient
    @JsonProperty("waf")
    @JsonView({ AllViews.FormInfo.class, AllViews.RestViewApplication2_1.class })
    private Map<String, Object> getWafRest() {

        if (waf == null) {
            return null;
        }

        Map<String, Object> map = new HashMap<String, Object>();

        map.put("id", waf.getId());
        map.put("name", waf.getName());

        return map;
    }


	@OneToMany(mappedBy = "application", cascade = CascadeType.ALL)
    @JsonIgnore
	public List<ApplicationChannel> getChannelList() {
		return channelList;
	}

	public void setChannelList(List<ApplicationChannel> channelList) {
		this.channelList = channelList;
	}
	
	@OneToMany(mappedBy = "application", cascade = CascadeType.ALL)
    @JsonIgnore
	public List<ScanQueueTask> getScanQueueTasks() {
		return(this.scanQueueTasks);
	}
	
	public void setScanQueueTasks(List<ScanQueueTask> scanQueueTasks) {
		this.scanQueueTasks = scanQueueTasks;
	}

    @OneToMany(mappedBy = "application", cascade = CascadeType.ALL)
    @JsonIgnore
    public List<ScheduledScan> getScheduledScans() {
        return scheduledScans;
    }

    public void setScheduledScans(List<ScheduledScan> scheduledScans) {
        this.scheduledScans = scheduledScans;
    }

    @OneToMany(mappedBy = "application")
	@OrderBy("importTime DESC")
    @JsonView(AllViews.RestViewApplication2_1.class)
    public List<Scan> getScans() {
		return scans;
	}

	public void setScans(List<Scan> scans) {
		this.scans = scans;
	}
	
	@OneToMany(mappedBy = "application", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<AccessControlApplicationMap> getAccessControlApplicationMaps() {
		return accessControlApplicationMaps;
	}

	public void setAccessControlApplicationMaps(List<AccessControlApplicationMap> accessControlApplicationMaps) {
		this.accessControlApplicationMaps = accessControlApplicationMaps;
	}

	@OneToMany(mappedBy = "application", cascade = CascadeType.ALL)
	@OrderBy("genericSeverity, genericVulnerability")
    @JsonIgnore
	public List<Vulnerability> getVulnerabilities() {
		return vulnerabilities;
	}

	public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}
	
	@Column(length = 256)
    @JsonIgnore
	public String getProjectRoot() {
		return projectRoot;
	}
	
	public void setProjectRoot(String projectRoot) {
		this.projectRoot = projectRoot;
	}
	
	@Column(length = 256)
    @JsonIgnore
	public String getRootPath() {
		return rootPath;
	}

	public void setRootPath(String rootPath) {
		this.rootPath = rootPath;
	}
	
	@OneToMany(mappedBy = "application")
    @JsonIgnore
	public List<RemoteProviderApplication> getRemoteProviderApplications() {
		return remoteProviderApplications;
	}

	public void setRemoteProviderApplications(
			List<RemoteProviderApplication> remoteProviderApplications) {
		this.remoteProviderApplications = remoteProviderApplications;
	}	

	@OneToMany(mappedBy = "application")
	@JsonIgnore
	public List<Document> getDocuments() {
		return documents;
	}

	public void setDocuments(List<Document> documents) {
		this.documents = documents;
	}
	
	@OneToMany(mappedBy = "application")
    @JsonIgnore
	public List<VulnerabilityFilter> getFilters() {
		return filters;
	}

	public void setFilters(List<VulnerabilityFilter> filters) {
		this.filters = filters;
	}
	
	@ManyToOne
	@JoinColumn(name = "applicationCriticalityId")
    @JsonView(Object.class)
	public ApplicationCriticality getApplicationCriticality() {
		return applicationCriticality;
	}

	public void setApplicationCriticality(ApplicationCriticality applicationCriticality) {
		this.applicationCriticality = applicationCriticality;
	}
	
	public void setVulnerabilityReport(List<Integer> vulnReport) {
		this.reportList = vulnReport;

        setInfoVulnCount(reportList.get(0));
        setLowVulnCount(reportList.get(1));
        setMediumVulnCount(reportList.get(2));
        setHighVulnCount(reportList.get(3));
        setCriticalVulnCount(reportList.get(4));
        setTotalVulnCount(reportList.get(5));
	}

    @Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestViewApplication2_1.class })
    public Integer getTotalVulnCount() {
        return totalVulnCount == null ? 0 : totalVulnCount;
    }

    public void setTotalVulnCount(Integer totalVulnCount) {
        this.totalVulnCount = totalVulnCount;
    }

    @Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestViewApplication2_1.class })
    public Integer getInfoVulnCount() {
        return infoVulnCount == null ? 0 : infoVulnCount;
    }

    @Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestViewApplication2_1.class })
    public void setInfoVulnCount(Integer infoVulnCount) {
        this.infoVulnCount = infoVulnCount;
    }

    public Integer getLowVulnCount() {
        return lowVulnCount == null ? 0 : lowVulnCount;
    }

    @Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestViewApplication2_1.class })
    public void setLowVulnCount(Integer lowVulnCount) {
        this.lowVulnCount = lowVulnCount;
    }

    public Integer getMediumVulnCount() {
        return mediumVulnCount == null ? 0 : mediumVulnCount;
    }

    @Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestViewApplication2_1.class })
    public void setMediumVulnCount(Integer mediumVulnCount) {
        this.mediumVulnCount = mediumVulnCount;
    }

    public Integer getHighVulnCount() {
        return highVulnCount == null ? 0 : highVulnCount;
    }

    @Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestViewApplication2_1.class })
    public void setHighVulnCount(Integer highVulnCount) {
        this.highVulnCount = highVulnCount;
    }

    @Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestViewApplication2_1.class })
    public Integer getCriticalVulnCount() {
        return criticalVulnCount == null ? 0 : criticalVulnCount;
    }

    public void setCriticalVulnCount(Integer criticalVulnCount) {
        this.criticalVulnCount = criticalVulnCount;
    }

	@Transient
	@JsonIgnore
	public List<Finding> getFindingList() {
		if (findingList != null)
			return findingList;
		List<Finding> findings = new ArrayList<Finding>();
		for (Vulnerability vuln : getVulnerabilities()) {
			for (Finding finding : vuln.getFindings()) {
				if (finding != null) {
					findings.add(finding);
				}
			}
		}
		findingList = findings;
		return findings;
	}
	
	@Transient
	@JsonIgnore
	public List<Vulnerability> getActiveVulnerabilities() {
		List<Vulnerability> result = new ArrayList<Vulnerability>();
		for(Vulnerability vuln : vulnerabilities) {
			if(vuln.isActive() && !vuln.getHidden() && !vuln.getIsFalsePositive()){
				result.add(vuln);
			}
		}
		return result;
	}
	
	@Transient
	@JsonIgnore
	public List<Vulnerability> getClosedVulnerabilities() {
		List<Vulnerability> result = new ArrayList<Vulnerability>();
		for(Vulnerability vuln : vulnerabilities) {
			if(!vuln.isActive()){
				result.add(vuln);
			}
		}
		return result;
	}
	
	@Transient
	@JsonIgnore
	public List<ApplicationChannel> getUploadableChannels() {
		
		if (uploadableChannels != null)
			return uploadableChannels;
		
		List<ApplicationChannel> normalList = getChannelList();
		if (normalList == null || normalList.size() == 0)
			return new ArrayList<ApplicationChannel>();
		
		Set<String> doNotIncludeSet = new HashSet<String>();
		doNotIncludeSet.add(ScannerType.MANUAL.getFullName());
		doNotIncludeSet.add(ScannerType.SENTINEL.getFullName());
		doNotIncludeSet.add(ScannerType.VERACODE.getFullName());
		doNotIncludeSet.add(ScannerType.QUALYSGUARD_WAS.getFullName());
		
		List<ApplicationChannel> returnList = new ArrayList<ApplicationChannel>();
	
		for (ApplicationChannel channel : normalList) {
			if (channel != null && channel.getChannelType() != null 
					&& channel.getChannelType().getName() != null
					&& !doNotIncludeSet.contains(channel.getChannelType().getName())) {
				returnList.add(channel);
			}
		}
		uploadableChannels = returnList;
		return returnList;
	}
	
	@Column(length = ENUM_LENGTH)
    @JsonView(AllViews.FormInfo.class)
	public String getFrameworkType() {
		return frameworkType;
	}

	public void setFrameworkType(String frameworkType) {
		this.frameworkType = frameworkType;
	}

	@Column(length = ENUM_LENGTH)
    @JsonIgnore
	public String getSourceCodeAccessLevel() {
		return sourceCodeAccessLevel;
	}

	public void setSourceCodeAccessLevel(String sourceCodeAccessLevel) {
		this.sourceCodeAccessLevel = sourceCodeAccessLevel;
	}

	@Column(length = URL_LENGTH)
    @JsonView(AllViews.FormInfo.class)
	public String getRepositoryUrl() {
		return repositoryUrl;
	}

	public void setRepositoryUrl(String repositoryUrl) {
		this.repositoryUrl = repositoryUrl;
	}

    @JsonView(AllViews.FormInfo.class)
    public String getRepositoryBranch() {
        return repositoryBranch;
    }

    public void setRepositoryBranch(String repositoryBranch) {
        this.repositoryBranch = repositoryBranch;
    }

    @JsonIgnore
    public String getRepositoryDBBranch() {
        return repositoryDBBranch;
    }

    public void setRepositoryDBBranch(String repositoryDBBranch) {
        this.repositoryDBBranch = repositoryDBBranch;
    }

    @Transient
    @JsonView(AllViews.FormInfo.class)
    public String getRepositoryUserName() {
        return repositoryUserName;
    }

    public void setRepositoryUserName(String repositoryUserName) {
        this.repositoryUserName = repositoryUserName;
    }

    @Transient
    @JsonView(AllViews.FormInfo.class)
    public String getRepositoryPassword() {
        return repositoryPassword;
    }

    public void setRepositoryPassword(String repositoryPassword) {
        this.repositoryPassword = repositoryPassword;
    }

    @Column(length = 1024)
    @JsonIgnore
    public String getRepositoryEncryptedPassword() {
        return repositoryEncryptedPassword;
    }

    public void setRepositoryEncryptedPassword(String repositoryEncryptedPassword) {
        this.repositoryEncryptedPassword = repositoryEncryptedPassword;
    }

    @Column(length = 1024)
    @JsonIgnore
    public String getRepositoryEncryptedUserName() {
        return repositoryEncryptedUserName;
    }

    public void setRepositoryEncryptedUserName(String repositoryEncryptedUserName) {
        this.repositoryEncryptedUserName = repositoryEncryptedUserName;
    }

    @Column(length = URL_LENGTH)
    @JsonView(AllViews.FormInfo.class)
	public String getRepositoryFolder() {
		return repositoryFolder;
	}

	public void setRepositoryFolder(String repositoryFolder) {
		this.repositoryFolder = repositoryFolder;
	}

	@Transient
    @JsonIgnore
	public FrameworkType getFrameworkTypeEnum() {
		return FrameworkType.getFrameworkType(frameworkType);
	}
	
	@Transient
    @JsonIgnore
	public SourceCodeAccessLevel getSourceCodeAccessLevelEnum() {
		return SourceCodeAccessLevel.getSourceCodeAccessLevel(sourceCodeAccessLevel);
	}

    @Transient
    @JsonIgnore
    // this uses VulnerabilityMarker[] to ease JSON transitions
    public List<VulnerabilityMarker> getMarkers() {
        List<VulnerabilityMarker> markers = new ArrayList<VulnerabilityMarker>();

        for (Vulnerability vulnerability : getVulnerabilities()) {
            if (vulnerability != null) {
                markers.add(vulnerability.toVulnerabilityMarker());
            }
        }

        return markers;
    }

    public static class Info {

        public String applicationName, organizationName, applicationId;

        public String getApplicationId() {
            return applicationId;
        }

        public String getOrganizationName() {
            return organizationName;
        }

        public String getApplicationName() {
            return applicationName;
        }

    }

    @Transient
    @JsonIgnore
    public Info getInfo() {
        Info info = new Info();

        info.applicationId    = getId().toString();
        info.organizationName = getOrganization().getName();
        info.applicationName  = getName();

        return info;
    }

    @Transient
    public void addVulnerability(Vulnerability vuln) {
        if (!this.getVulnerabilities().contains(vuln))
            this.getVulnerabilities().add(vuln);
    }

    // TODO exclude from default ObjectMapper
    @Transient
    @JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.VulnSearchApplications.class, AllViews.RestViewTag.class })
    private Map<String, Object> getTeam() {
        Organization team = getOrganization();

        Map<String, Object> map = new HashMap<String, Object>();
        if (team != null) {
            map.put("id", team.getId());
            map.put("name", team.getName());
        }
        return map;
    }

    public void setTeam(Organization organization) {
        this.organization = organization;
    }

    @Transient
    @JsonView(AllViews.RestViewApplication2_1.class)
    @JsonProperty("organization")
    public Map<String, Object> getOrganizationRest() {
        Organization team = getOrganization();

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("id", team.getId());
        map.put("name", team.getName());

        return map;
    }

    @Column(nullable = true)
    @JsonView(AllViews.FormInfo.class)
    public Boolean getSkipApplicationMerge() {
        return skipApplicationMerge != null && skipApplicationMerge;
    }

    public void setSkipApplicationMerge(Boolean isSkipApplicationMerge) {
        this.skipApplicationMerge = isSkipApplicationMerge;
    }

//    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @ManyToMany(cascade = CascadeType.ALL)
    @JoinTable(name="Application_Tag",
            joinColumns={@JoinColumn(name="Application_Id")},
            inverseJoinColumns={@JoinColumn(name="Tag_Id")})
    @JsonIgnore
    public List<Tag> getTags() {
        return tags;
    }

    public void setTags(List<Tag> tags) {
        this.tags = tags;
    }
}
