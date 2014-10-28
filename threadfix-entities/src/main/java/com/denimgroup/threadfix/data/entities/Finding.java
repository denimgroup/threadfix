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
import org.hibernate.annotations.Cascade;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.Calendar;
import java.util.List;

@Entity
@Table(name = "Finding")
public class Finding extends AuditableEntity implements FindingLike {

	private static final long serialVersionUID = 5978786078427181952L;

	public static final int LONG_DESCRIPTION_LENGTH = 2047;
	public static final int ATTACK_STRING_LENGTH = 1048575;
	public static final int ATTACK_REQUEST_LENGTH = 1048575;
	public static final int ATTACK_RESPONSE_LENGTH = 1048575;
	public static final int SCANNER_DETAIL_LENGTH = 1048575;
	public static final int SCANNER_RECOMMENDATION_LENGTH = 1048575;
	public static final int RAW_FINDING_LENGTH = 1048575;
	public static final int NATIVE_ID_LENGTH = 50;
	public static final int URL_REFERENCE_LENGTH = 256;
	public static final int SOURCE_FILE_LOCATION_LENGTH = 128;

    // TODO figure out the appropriate place for this
    public static final int NUMBER_ITEM_PER_PAGE = 100;


    private Vulnerability vulnerability;

	private Scan scan;

	@Size(max = LONG_DESCRIPTION_LENGTH, message = "{errors.maxlength} "
			+ LONG_DESCRIPTION_LENGTH + ".")
	private String longDescription;

	@Size(max = ATTACK_STRING_LENGTH, message = "{errors.maxlength} "
			+ ATTACK_STRING_LENGTH + ".")
	private String attackString;

	@Size(max = ATTACK_REQUEST_LENGTH, message = "{errors.maxlength} "
			+ ATTACK_REQUEST_LENGTH + ".")
	private String attackRequest;

	@Size(max = ATTACK_RESPONSE_LENGTH, message = "{errors.maxlength} "
			+ ATTACK_RESPONSE_LENGTH + ".")
	private String attackResponse;

	@Size(max = SCANNER_DETAIL_LENGTH, message = "{errors.maxlength} "
			+ SCANNER_DETAIL_LENGTH + ".")
	private String scannerDetail;

	@Size(max = SCANNER_RECOMMENDATION_LENGTH, message = "{errors.maxlength} "
			+ SCANNER_RECOMMENDATION_LENGTH + ".")
	private String scannerRecommendation;

	@Size(max = RAW_FINDING_LENGTH, message = "{errors.maxlength} "
			+ RAW_FINDING_LENGTH + ".")
	private String rawFinding;

    @Size(max = URL_REFERENCE_LENGTH, message = "{errors.maxlength} "
            + URL_REFERENCE_LENGTH + ".")
    private String urlReference = null;

	private ChannelVulnerability channelVulnerability;

	@Size(max = NATIVE_ID_LENGTH, message = "{errors.maxlength} "
			+ NATIVE_ID_LENGTH + ".")
	private String nativeId;

	@Size(max = NATIVE_ID_LENGTH, message = "{errors.maxlength} "
			+ NATIVE_ID_LENGTH + ".")
	private String displayId;

	private ChannelSeverity channelSeverity;
	private SurfaceLocation surfaceLocation;
	private StaticPathInformation staticPathInformation;

	private int numberMergedResults = 1;
	private Integer entryPointLineNumber = -1;

	@Size(max = SOURCE_FILE_LOCATION_LENGTH, message = "{errors.maxlength} "
			+ SOURCE_FILE_LOCATION_LENGTH + ".")
	private String sourceFileLocation;
	private boolean isStatic;
	private boolean isFirstFindingForVuln;
	private boolean isMarkedFalsePositive = false;

	private User user;

	private List<DataFlowElement> dataFlowElements;
	private List<ScanRepeatFindingMap> scanRepeatFindingMaps;

	private String calculatedUrlPath = "", calculatedFilePath = "";
	private Dependency dependency;

	@Override
	@ManyToOne
	@JsonIgnore
	@JoinColumn(name = "vulnerabilityId")
	public Vulnerability getVulnerability() {
		return vulnerability;
	}

	public void setVulnerability(Vulnerability vulnerability) {
		this.vulnerability = vulnerability;
	}

	@ManyToOne
	@JoinColumn(name = "scanId")
	@JsonIgnore
	public Scan getScan() {
		return scan;
	}

	public void setScan(Scan scan) {
		this.scan = scan;
	}

    @ManyToOne
	@JoinColumn(name = "channelVulnerabilityId")
	@JsonView({AllViews.TableRow.class, AllViews.VulnerabilityDetail.class})
	public ChannelVulnerability getChannelVulnerability() {
		return channelVulnerability;
	}

	public void setChannelVulnerability(
			ChannelVulnerability channelVulnerability) {
		this.channelVulnerability = channelVulnerability;
	}

	@Column(length = NATIVE_ID_LENGTH)
    @JsonView({AllViews.RestView2_1.class, AllViews.VulnerabilityDetail.class})
    public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}

    // TODO add more information to the native ID
    @Transient
    @JsonIgnore
    public String getNonMergingKey() {
        return getDependency() == null ? getNativeId() : getDependency().getKey();
    }

	@Column(length = NATIVE_ID_LENGTH)
    @JsonView({AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.VulnerabilityDetail.class })
	public String getDisplayId() {
		return displayId;
	}

	public void setDisplayId(String displayId) {
		this.displayId = displayId;
	}

	@ManyToOne
	@JoinColumn(name = "channelSeverityId")
	@JsonView({AllViews.TableRow.class, AllViews.VulnerabilityDetail.class})
	public ChannelSeverity getChannelSeverity() {
		return channelSeverity;
	}

	public void setChannelSeverity(ChannelSeverity channelSeverity) {
		this.channelSeverity = channelSeverity;
	}

	@OneToOne(cascade = CascadeType.ALL)
	@JoinColumn(name = "surfaceLocationId")
	@JsonView({AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.VulnerabilityDetail.class})
	public SurfaceLocation getSurfaceLocation() {
		return surfaceLocation;
	}

	public void setSurfaceLocation(SurfaceLocation surfaceLocation) {
		this.surfaceLocation = surfaceLocation;
	}

	@OneToOne(cascade = CascadeType.ALL)
	@JoinColumn(name = "staticPathInformationId")
	public StaticPathInformation getStaticPathInformation() {
		return staticPathInformation;
	}

	public void setStaticPathInformation(
			StaticPathInformation staticPathInformation) {
		this.staticPathInformation = staticPathInformation;
	}

	@OneToMany(mappedBy = "finding")
	@Cascade({ org.hibernate.annotations.CascadeType.ALL })
	@OrderBy("sequence DESC")
    @JsonView({ AllViews.RestView2_1.class, AllViews.VulnerabilityDetail.class })
	public List<DataFlowElement> getDataFlowElements() {
		return dataFlowElements;
	}

	public void setDataFlowElements(List<DataFlowElement> dataFlowElements) {
		this.dataFlowElements = dataFlowElements;
	}

	@Column(nullable = false)
	public boolean getIsStatic() {
		return isStatic;
	}

	public void setIsStatic(boolean isStatic) {
		this.isStatic = isStatic;
	}

	@OneToMany(mappedBy = "finding", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<ScanRepeatFindingMap> getScanRepeatFindingMaps() {
		return scanRepeatFindingMaps;
	}

	public void setScanRepeatFindingMaps(
			List<ScanRepeatFindingMap> scanRepeatFindingMaps) {
		this.scanRepeatFindingMaps = scanRepeatFindingMaps;
	}

    @JsonView(AllViews.RestView2_1.class)
	public String getSourceFileLocation() {
		return sourceFileLocation;
	}

	@Column(length = SOURCE_FILE_LOCATION_LENGTH)
	public void setSourceFileLocation(String sourceFileLocation) {
		this.sourceFileLocation = sourceFileLocation;
	}

	@Column
	@JsonView({AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.VulnerabilityDetail.class })
	public String getCalculatedUrlPath() {
		return calculatedUrlPath;
	}

	public void setCalculatedUrlPath(String calculatedUrlPath) {
		this.calculatedUrlPath = calculatedUrlPath;
	}

	@Column
    @JsonView({AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.VulnerabilityDetail.class })
	public String getCalculatedFilePath() {
		return calculatedFilePath;
	}

	public void setCalculatedFilePath(String calculatedFilePath) {
		this.calculatedFilePath = calculatedFilePath;
	}

	@Column
	public void setNumberMergedResults(int numMergedResults) {
		this.numberMergedResults = numMergedResults;
	}

	@JsonView(AllViews.TableRow.class)
	public int getNumberMergedResults() {
		return numberMergedResults;
	}

	@Column
	public Integer getEntryPointLineNumber() {
		if (entryPointLineNumber == null) {
			return -1;
		}
		return entryPointLineNumber;
	}

	public void setEntryPointLineNumber(Integer entryPointLineNumber) {
		this.entryPointLineNumber = entryPointLineNumber;
	}

	@ManyToOne
	@JoinColumn(name = "userId")
	@JsonIgnore
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	@Column(length = LONG_DESCRIPTION_LENGTH)
    @JsonView(AllViews.RestView2_1.class)
	public void setLongDescription(String longDescription) {
		this.longDescription = longDescription;
	}

	public String getLongDescription() {
		return longDescription;
	}

    @JsonView(AllViews.RestView2_1.class)
    @Column(length = ATTACK_STRING_LENGTH)
	public String getAttackString() {
		return attackString;
	}

    public void setAttackString(String attackString) {
        this.attackString = attackString;
    }

    @JsonView(AllViews.RestView2_1.class)
    @Column(length = ATTACK_REQUEST_LENGTH)
	public String getAttackRequest() {
		return attackRequest;
	}

	public void setAttackRequest(String attackRequest) {
		this.attackRequest = attackRequest;
	}

    @JsonView(AllViews.RestView2_1.class)
    @Column(length = ATTACK_RESPONSE_LENGTH)
	public String getAttackResponse() {
		return attackResponse;
	}

	public void setAttackResponse(String attackResponse) {
		this.attackResponse = attackResponse;
	}

    @Column(length = SCANNER_DETAIL_LENGTH)
	public String getScannerDetail() {
		return scannerDetail;
	}

	public void setScannerDetail(String scannerDetail) {
		this.scannerDetail = scannerDetail;
	}

    @Column(length = SCANNER_RECOMMENDATION_LENGTH)
	public String getScannerRecommendation() {
		return scannerRecommendation;
	}

	public void setScannerRecommendation(String scannerRecommendation) {
		this.scannerRecommendation = scannerRecommendation;
	}

	@Column(length = URL_REFERENCE_LENGTH)
	public String getUrlReference() {
		return urlReference;
	}

	public void setUrlReference(String urlReference) {
		this.urlReference = urlReference;
	}

	@Column(length = RAW_FINDING_LENGTH)
	public String getRawFinding() {
		return rawFinding;
	}

	public void setRawFinding(String rawFinding) {
		this.rawFinding = rawFinding;
	}
	
	@Column(nullable = false)
	public boolean isFirstFindingForVuln() {
		return isFirstFindingForVuln;
	}

	public void setFirstFindingForVuln(boolean isFirstFindingForVuln) {
		this.isFirstFindingForVuln = isFirstFindingForVuln;
	}

	@Column
	public boolean isMarkedFalsePositive() {
		return isMarkedFalsePositive;
	}

	public void setMarkedFalsePositive(boolean isMarkedFalsePositive) {
		this.isMarkedFalsePositive = isMarkedFalsePositive;
	}

	@OneToOne(cascade = CascadeType.ALL)
	@JoinColumn(name = "dependencyId")
	@JsonView({ AllViews.TableRow.class, AllViews.RestView2_1.class, AllViews.VulnerabilityDetail.class })
	public Dependency getDependency() {
		return dependency;
	}

	public void setDependency(Dependency dependency) {
		this.dependency = dependency;
	}

	@Transient
	@JsonView({ AllViews.TableRow.class, AllViews.VulnerabilityDetail.class })
	private String getScannerName() {
		return getScan().getApplicationChannel().getChannelType().getName();
	}

	@Transient
	@JsonView({ AllViews.TableRow.class, AllViews.VulnerabilityDetail.class })
	private Integer getScanId() {
		return getScan().getId();
	}

	@Transient
	@JsonView(AllViews.TableRow.class)
	private Calendar getImportTime() {
		return getScan().getImportTime();
	}

	@Transient
	@JsonView(AllViews.TableRow.class)
	private User getScanOrManualUser() {
		if (getScan().getUser() != null) {
			return getScan().getUser();
		} else {
			return getUser();
		}
	}

    @Transient
    @JsonView(AllViews.RestView2_1.class)
    private String getVulnerabilityType() {
        return getChannelVulnerability() == null ? null :
                getChannelVulnerability().getName();
    }

    @Transient
    @JsonView(AllViews.TableRow.class)
    private String getGenericVulnerabilityName() {
        return getChannelVulnerability() == null ? null :
                getChannelVulnerability().getGenericVulnerability() == null ? null :
                getChannelVulnerability().getGenericVulnerability().getName();
    }

    @Transient
    @JsonView(AllViews.RestView2_1.class)
    private String getSeverity() {
        return getChannelSeverity() == null ? null :
                getChannelSeverity().getName();
    }

    @Override
    public String toString() {

        if (dependency != null) {
            return "Finding{ Dependency{ CVEID=" + dependency.getCve() + "}}";
        } else if (isStatic) {
            return "Finding{ " +
                    "staticPath=" + getSourceFileLocation() +
                    ", channelSeverity=" + channelSeverity +
                    ", channelVulnerability=" + channelVulnerability +
                    "}";
        } else {
            return "Finding {" +
                    "channelSeverity=" + channelSeverity +
                    ", channelVulnerability=" + channelVulnerability +
                    ", surfaceLocation=" + surfaceLocation +
                    '}';
        }
    }
}
