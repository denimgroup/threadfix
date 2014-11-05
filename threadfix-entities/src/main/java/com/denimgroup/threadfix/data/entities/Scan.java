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

import com.denimgroup.threadfix.views.AllViews;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonView;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

@Entity
@Table(name = "Scan")
public class Scan extends BaseEntity implements Iterable<Finding> {

	private static final long serialVersionUID = -8461350611851383656L;

	private ApplicationChannel applicationChannel;
	private Calendar importTime;
	private Application application;
	private Integer numberClosedVulnerabilities=0;
	private Integer numberNewVulnerabilities=0;
	private Integer numberOldVulnerabilities=0;
	private Integer numberResurfacedVulnerabilities=0;
	private Integer numberTotalVulnerabilities=0;
	private Integer numberHiddenVulnerabilities=0;
	private Integer numberRepeatResults=0;
	private Integer numberRepeatFindings=0;
	
	private Long numberInfoVulnerabilities = 0L, numberLowVulnerabilities = 0L,
			numberMediumVulnerabilities = 0L, numberHighVulnerabilities = 0L,
            numberCriticalVulnerabilities = 0L;

    private User user;

    private List<ScanRepeatFindingMap>       scanRepeatFindingMaps;
    private List<ScanReopenVulnerabilityMap> scanReopenVulnerabilityMaps;
    private List<ScanCloseVulnerabilityMap>  scanCloseVulnerabilityMaps;

    // TODO probably rename this - it's for the graphs
    private Integer numberOldVulnerabilitiesInitiallyFromThisChannel;

    private List<Finding> findings;

    private Integer numWithoutChannelVulns    = null;
    private Integer numWithoutGenericMappings = null;

    private Integer totalNumberSkippedResults       = null;
    private Integer totalNumberFindingsMergedInScan = null;

    // These are for determining what type of scanner was used
    private static final List<String> DYNAMIC_TYPES = list(
            ScannerType.ACUNETIX_WVS.getFullName(),
            ScannerType.APPSCAN_ENTERPRISE.getFullName(),
            ScannerType.ARACHNI.getFullName(),
            ScannerType.BURPSUITE.getFullName(),
            ScannerType.NESSUS.getFullName(),
            ScannerType.NETSPARKER.getFullName(),
            ScannerType.NTO_SPIDER.getFullName(),
            ScannerType.SKIPFISH.getFullName(),
            ScannerType.W3AF.getFullName(),
            ScannerType.WEBINSPECT.getFullName(),
            ScannerType.ZAPROXY.getFullName(),
            ScannerType.QUALYSGUARD_WAS.getFullName(),
            ScannerType.APPSCAN_DYNAMIC.getFullName(),
            ScannerType.CENZIC_HAILSTORM.getFullName());

    private static final List<String> STATIC_TYPES = list(
            ScannerType.APPSCAN_SOURCE.getFullName(),
            ScannerType.FINDBUGS.getFullName(),
            ScannerType.FORTIFY.getFullName(),
            ScannerType.VERACODE.getFullName(),
            ScannerType.CAT_NET.getFullName(),
            ScannerType.BRAKEMAN.getFullName(),
            ScannerType.CHECKMARX.getFullName());
    private static final List<String> MIXED_TYPES  = Arrays.asList(ScannerType.SENTINEL.getFullName());
    private static final String       DYNAMIC      = "Dynamic", STATIC = "Static", MIXED = "Mixed";

    @Size(max = 255, message = "{errors.maxlength} 255.")
    private String filePathRoot;
    @Size(max = 255, message = "{errors.maxlength} 255.")
    private String urlPathRoot;

    @ManyToOne(cascade = CascadeType.MERGE)
    @JoinColumn(name = "applicationChannelId")
    @JsonIgnore
    public ApplicationChannel getApplicationChannel() {
        return applicationChannel;
    }

    public void setApplicationChannel(ApplicationChannel applicationChannel) {
        this.applicationChannel = applicationChannel;
    }

    @Temporal(TemporalType.TIMESTAMP)
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class})
    public Calendar getImportTime() {
        return importTime;
    }

    public void setImportTime(Calendar importTime) {
        this.importTime = importTime;
    }

    @ManyToOne
    @JoinColumn(name = "applicationId")
    @JsonIgnore
    public Application getApplication() {
        return application;
    }

    public void setApplication(Application application) {
        this.application = application;
    }

    @ManyToOne
    @JoinColumn(nullable = true, name = "userId")
    @JsonIgnore
    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
    @JsonView(AllViews.RestViewScan2_1.class)
    public List<Finding> getFindings() {
        return findings;
    }

    public void setFindings(List<Finding> findings) {
        this.findings = findings;
    }

    @Column(length = 256)
    public String getFilePathRoot() {
        return filePathRoot;
    }

    public void setFilePathRoot(String filePathRoot) {
        this.filePathRoot = filePathRoot;
    }

    @Column(length = 256)
    public String getUrlPathRoot() {
        return urlPathRoot;
    }

    public void setUrlPathRoot(String urlPathRoot) {
        this.urlPathRoot = urlPathRoot;
    }

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
    @JsonIgnore
    public List<ScanRepeatFindingMap> getScanRepeatFindingMaps() {
        return scanRepeatFindingMaps;
    }

    public void setScanRepeatFindingMaps(List<ScanRepeatFindingMap> scanRepeatFindingMaps) {
        this.scanRepeatFindingMaps = scanRepeatFindingMaps;
    }

    @JsonIgnore
    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
	public List<ScanReopenVulnerabilityMap> getScanReopenVulnerabilityMaps() {
		return scanReopenVulnerabilityMaps;
	}

	public void setScanReopenVulnerabilityMaps(List<ScanReopenVulnerabilityMap> ScanReopenVulnerabilityMaps) {
		this.scanReopenVulnerabilityMaps = ScanReopenVulnerabilityMaps;
	}

    @JsonIgnore
	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
	public List<ScanCloseVulnerabilityMap> getScanCloseVulnerabilityMaps() {
		return scanCloseVulnerabilityMaps;
	}

	public void setScanCloseVulnerabilityMaps(List<ScanCloseVulnerabilityMap> ScanCloseVulnerabilityMaps) {
		this.scanCloseVulnerabilityMaps = ScanCloseVulnerabilityMaps;
	}

	@Column
    @JsonView({AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class})
	public Integer getNumberClosedVulnerabilities() {
		return numberClosedVulnerabilities;
	}

	public void setNumberClosedVulnerabilities(Integer numberClosedVulnerabilities) {
		this.numberClosedVulnerabilities = numberClosedVulnerabilities;
	}

    @JsonView({AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class})
	@Column
	public Integer getNumberNewVulnerabilities() {
		return numberNewVulnerabilities;
	}

	public void setNumberNewVulnerabilities(Integer numberNewVulnerabilities) {
		this.numberNewVulnerabilities = numberNewVulnerabilities;
	}

    @JsonView({AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class})
	@Column
	public Integer getNumberOldVulnerabilities() {
		return numberOldVulnerabilities;
	}

	public void setNumberOldVulnerabilities(Integer numberOldVulnerabilities) {
		this.numberOldVulnerabilities = numberOldVulnerabilities;
	}
	
	/**
	 * Keeping track of this information allows us to produce scans without extensive recalculation,
	 * because we don't have to track down which application channel we should count a vulnerability for.
	 * 
	 * This may lead to a small bug if a vuln is opened in one channel, then found in another and
	 * subsequently closed there. This needs to be looked into.
	 * @return
	 */
	@Column
    @JsonView(AllViews.RestViewScanStatistic.class)
	public Integer getNumberOldVulnerabilitiesInitiallyFromThisChannel() {
		return numberOldVulnerabilitiesInitiallyFromThisChannel;
	}

	public void setNumberOldVulnerabilitiesInitiallyFromThisChannel(
			Integer numberOldVulnerabilitiesInitiallyFromThisChannel) {
		this.numberOldVulnerabilitiesInitiallyFromThisChannel = numberOldVulnerabilitiesInitiallyFromThisChannel;
	}

	@Column
    @JsonView({AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class})
    public Integer getNumberResurfacedVulnerabilities() {
		return numberResurfacedVulnerabilities;
	}

	public void setNumberResurfacedVulnerabilities(Integer numberResurfacedVulnerabilities) {
		this.numberResurfacedVulnerabilities = numberResurfacedVulnerabilities;
	}

	@Column
    @JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
    public Integer getNumberTotalVulnerabilities() {
		return numberTotalVulnerabilities;
	}

	public void setNumberTotalVulnerabilities(Integer numberTotalVulnerabilities) {
		this.numberTotalVulnerabilities = numberTotalVulnerabilities;
	}

    @JsonView({ AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
    @Column
	public Integer getNumberRepeatFindings() {
		return numberRepeatFindings;
	}

	public void setNumberRepeatFindings(Integer numberRepeatFindings) {
		this.numberRepeatFindings = numberRepeatFindings;
	}

    @JsonView({ AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
    @Column
	public Integer getNumberRepeatResults() {
		return numberRepeatResults;
	}

	public void setNumberRepeatResults(Integer numberRepeatResults) {
		this.numberRepeatResults = numberRepeatResults;
	}
	
	@Transient
	public Integer getNumWithoutGenericMappings() {
		return numWithoutGenericMappings;
	}
	
	public void setNumWithoutGenericMappings(Integer numWithoutGenericMappings) {
		this.numWithoutGenericMappings = numWithoutGenericMappings;
	}

	@Transient
	public Integer getNumWithoutChannelVulns() {
		return numWithoutChannelVulns;
	}
	
	public void setNumWithoutChannelVulns(Integer numWithoutChannelVulns) {
		this.numWithoutChannelVulns = numWithoutChannelVulns;
	}
	
	@Transient
	public Integer getTotalNumberSkippedResults() {
		return totalNumberSkippedResults;
	}
	
	public void setTotalNumberSkippedResults(Integer totalNumberSkippedResults) {
		this.totalNumberSkippedResults = totalNumberSkippedResults;
	}
	
	@Transient
	public Integer getTotalNumberFindingsMergedInScan() {
		return totalNumberFindingsMergedInScan;
	}
	
	public void setTotalNumberFindingsMergedInScan(
			Integer totalNumberFindingsMergedInScan) {
		this.totalNumberFindingsMergedInScan = totalNumberFindingsMergedInScan;
	}

	// These two functions establish the order the integers come in and this
	// order should not be changed.
	@Transient
	@JsonIgnore
	public List<Integer> getReportList() {
		List<Integer> integerList = new ArrayList<Integer>();
		integerList.add(getId());
		integerList.add(getNumberTotalVulnerabilities());
		integerList.add(getNumberNewVulnerabilities());
		integerList.add(getNumberOldVulnerabilities());
		integerList.add(getNumberResurfacedVulnerabilities());
		integerList.add(getNumberClosedVulnerabilities());
		return integerList;
	}
	
	@JsonIgnore
	public static ScanTimeComparator getTimeComparator() {
		return new ScanTimeComparator();
	}

    @Override
    public Iterator<Finding> iterator() {
        return findings == null ? new ArrayList<Finding>().iterator() : findings.iterator();
    }

    static public class ScanTimeComparator implements Comparator<Scan> {
	
		@Override
		public int compare(Scan scan1, Scan scan2){
			Calendar scan1Time = scan1.getImportTime();
			Calendar scan2Time = scan2.getImportTime();
			
			if (scan1Time == null || scan2Time == null) {
				return 0;
			}
			
			return scan1Time.compareTo(scan2Time);
		}
	}

	@Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
	public Long getNumberInfoVulnerabilities() {
		return numberInfoVulnerabilities;
	}

	public void setNumberInfoVulnerabilities(Long numberInfoVulnerabilities) {
		this.numberInfoVulnerabilities = numberInfoVulnerabilities;
	}
	
	@Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
	public Long getNumberLowVulnerabilities() {
		return numberLowVulnerabilities;
	}

	public void setNumberLowVulnerabilities(Long numberLowVulnerabilities) {
		this.numberLowVulnerabilities = numberLowVulnerabilities;
	}
	
	@Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
	public Long getNumberMediumVulnerabilities() {
		return numberMediumVulnerabilities;
	}

	public void setNumberMediumVulnerabilities(Long numberMediumVulnerabilities) {
		this.numberMediumVulnerabilities = numberMediumVulnerabilities;
	}
	
	@Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
	public Long getNumberHighVulnerabilities() {
		return numberHighVulnerabilities;
	}

	public void setNumberHighVulnerabilities(Long numberHighVulnerabilities) {
		this.numberHighVulnerabilities = numberHighVulnerabilities;
	}
	
	@Column
    @JsonView({ AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
    public Long getNumberCriticalVulnerabilities() {
		return numberCriticalVulnerabilities;
	}

	public void setNumberCriticalVulnerabilities(
			Long numberCriticalVulnerabilities) {
		this.numberCriticalVulnerabilities = numberCriticalVulnerabilities;
	}
	
	@Column
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestViewScanStatistic.class})
    public Integer getNumberHiddenVulnerabilities() {
		if (numberHiddenVulnerabilities == null) {
			return 0;
		} else {
			return numberHiddenVulnerabilities;
		}
	}

	public void setNumberHiddenVulnerabilities(
			Integer numberHiddenVulnerabilities) {
		this.numberHiddenVulnerabilities = numberHiddenVulnerabilities;
	}

	@Transient
	public String getScannerType() {
		if (getApplicationChannel() != null && getApplicationChannel().getChannelType() != null
				&& getApplicationChannel().getChannelType().getName() != null) {
			String scannerName = getApplicationChannel().getChannelType().getName();
			if (DYNAMIC_TYPES.contains(scannerName)) {
				return DYNAMIC;
			} else if (STATIC_TYPES.contains(scannerName)) {
				return STATIC;
			} else if (MIXED_TYPES.contains(scannerName)) {
				return MIXED;
			}
		}

		return null;
	}

    @Transient
	public boolean isStatic() {
		return STATIC.equals(getScannerType());
	}

    // This should get serialized.
    @JsonView(AllViews.TableRow.class)
    @Transient
    private String getType() {
        String type = getApplicationChannel().getChannelType().getName();
        if (ChannelType.DYNAMIC_TYPES.contains(type)) {
            return ChannelType.DYNAMIC;
        } else if (ChannelType.STATIC_TYPES.contains(type)) {
            return ChannelType.STATIC;
        } else {
            return ChannelType.MIXED;
        }
    }

    // TODO figure out JSON serialization better
    @JsonView({ AllViews.TableRow.class, AllViews.RestViewScanStatistic.class})
    @Transient
    private Map<String, Object> getApp() {
        Application app = getApplication();

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("id", app.getId());
        map.put("name", app.getName());

        return map;
    }

    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class, AllViews.RestViewScanStatistic.class })
    @Transient
    private String getScannerName() {
        return getApplicationChannel().getChannelType().getName();
    }

    @JsonView({AllViews.TableRow.class, AllViews.RestViewScanStatistic.class})
    @Transient
    private Map<String, Object> getTeam() {
        Organization team = getApplication().getOrganization();

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("id", team.getId());
        map.put("name", team.getName());

        return map;
    }

    @JsonView({AllViews.TableRow.class, AllViews.RestViewScanStatistic.class})
    @Transient
    private Integer getApplicationChannelId(){
        return (getApplicationChannel()==null ? null : getApplicationChannel().getId());
    }

    @JsonView(AllViews.RestViewScanStatistic.class)
    @Transient
    private List<Map> getApplicationTags(){
        List<Map> maps = list();
        List<Tag> tags = getApplication().getTags();
        for (Tag tag: tags) {
            Map<String, Object> map = newMap();
            map.put("id", tag.getId());
            map.put("name", tag.getName());
            maps.add(map);
        }
        return maps;
    }
}
