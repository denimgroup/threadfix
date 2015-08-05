////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import org.hibernate.annotations.Type;
import org.hibernate.validator.constraints.URL;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Entity
@Table(name="ScanQueueTask")
public class ScanQueueTask extends AuditableEntity {

	private static final long serialVersionUID = 886166865576713403L;
	
	public enum ScanQueueTaskStatus {
		STATUS_QUEUED(1,"QUEUED"),
		STATUS_ASSIGNED(2, "ASSIGNED"),
		STATUS_COMPLETE_SUCCESSFUL(3, "COMPLETE_SUCCESSFUL"),
		STATUS_COMPLETE_DELETED(4, "COMPLETE_DELETED"),
		STATUS_COMPLETE_TIMEDOUT(5, "COMPLETE_TIMEDOUT"),
		STATUS_COMPLETE_FAILED(6, "COMPLETE_FAILED"),
		STATUS_UNKNOWN(7, "UNKNOWN");
		
		private int value;
		private String description;

        static ScanQueueTaskStatus getFromValue(int value) {
            ScanQueueTaskStatus returnStatus = null;

            for (ScanQueueTaskStatus status : values()) {
                if (status.getValue() == value) {
                    returnStatus = status;
                    break;
                }
            }

            return returnStatus;
        }
		
		public int getValue() {
			return this.value;
		}
		
		public String getDescription() {
			return this.description;
		}
		
		private ScanQueueTaskStatus(int value, String description) {
			this.value = value;
			this.description = description;
		}
	}

    public ScanQueueTask() {
        this(12);
    }

    public ScanQueueTask(int numHoursTilTimeout) {
        Date now = new Date();

        setCreateTime(now);

        Calendar myCal = Calendar.getInstance();
        //	TODO - Actually calculate the max finish time
        myCal.add(Calendar.HOUR, 12);
        setTimeoutTime(myCal.getTime());

        ScanStatus scanStatus = new ScanStatus();
        scanStatus.setTimestamp(now);
        SimpleDateFormat format = new SimpleDateFormat("dd-MM-yy:HH:mm:SS Z");
        scanStatus.setMessage("Scan queued at: " + format.format(now));
        scanStatus.setScanQueueTask(this);

        addScanStatus(scanStatus);
    }

	public final static String SCANAGENT_CONFIG_FILE_EXTENSION = "scanagtcfg";
	
	private int taskId;
	private Application application;
	private List<ScanStatus> scanStatuses;
	
	//	TODO - Determine if this is a String or a string/enumeration
	private String scanner;
	//	TODO - Determine if we need to treat this different
	private String version;
	
	private Date createTime;
	private Date startTime;
	private Date endTime;
	private Date timeoutTime;
	//	TODO - Make an enumeration for the various status options
	private int status;
	private String scanAgentInfo;
	private String secureKey;
	private String scanAgentInstanceSecureKey;
	private Document scanConfig;
	private String targetUrl;

	@Column
	public int taskId() {
		return this.taskId;
	}
	
	public void taskId(int taskId) {
		this.taskId = taskId;
	}
	
	@OneToMany(mappedBy = "scanQueueTask", cascade = CascadeType.ALL)
	public List<ScanStatus> getScanStatuses() {
		return this.scanStatuses;
	}
	
	public void setScanStatuses(List<ScanStatus> scanStatuses) {
		this.scanStatuses = scanStatuses;
	}

	@ManyToOne
	@JoinColumn(name = "applicationId")
	@JsonIgnore
	public Application getApplication() {
		return this.application;
	}
	
	public void setApplication(Application application) {
		this.application = application;
	}
	
	@Column(nullable=false)
    @JsonView(Object.class)
	public String getScanner() {
		ScannerType scannerType = ScannerType.getScannerType(scanner);
		return scannerType != null ? scannerType.getDisplayName() : scanner;
	}
	
	public void setScanner(String scanner) {
		this.scanner = scanner;
	}
	
	@Column
    @JsonView(Object.class)
	public String getVersion() {
		return this.version;
	}
	
	public void setVersion(String version) {
		this.version = version;
	}
	
	
	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable=false)
    @JsonView(Object.class)
	public Date getCreateTime() {
		return createTime;
	}

	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
    @JsonView(Object.class)
	public Date getStartTime() {
		return startTime;
	}

	public void setStartTime(Date startTime) {
		this.startTime = startTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
    @JsonView(Object.class)
	public Date getEndTime() {
		return endTime;
	}

	public void setEndTime(Date endTime) {
		this.endTime = endTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
    @JsonView(Object.class)
	public Date getTimeoutTime() {
		return timeoutTime;
	}

	public void setTimeoutTime(Date timeoutTime) {
		this.timeoutTime = timeoutTime;
	}

	@Column(nullable=false)
	public int getStatus() {

        return this.status;
	}
	
	public void setStatus(int status) {
		this.status = status;
	}

    @Transient
    public ScanQueueTaskStatus getTaskStatus() {
        return ScanQueueTaskStatus.getFromValue(status);
    }

    public void setTaskStatus(ScanQueueTaskStatus status) {
        setStatus(status.getValue());
    }

    @Transient
    @JsonView(Object.class)
    public String getStatusString() {
        return ScanQueueTaskStatus.getFromValue(status).description;
    }

	@Column
	@Type(type="text")
	public String getScanAgentInfo() {
		return this.scanAgentInfo;
	}
	
	public void setScanAgentInfo(String scanAgentInfo) {
		this.scanAgentInfo = scanAgentInfo;
	}

	@Column(length = 50)
	public String getSecureKey() {
		return secureKey;
	}

	public void setSecureKey(String secureKey) {
		this.secureKey = secureKey;
	}

	@Column(length = 50)
	public String getScanAgentInstanceSecureKey() {
		return scanAgentInstanceSecureKey;
	}

	public void setScanAgentInstanceSecureKey(String scanAgentInstanceSecureKey) {
		this.scanAgentInstanceSecureKey = scanAgentInstanceSecureKey;
	}

	@ManyToOne
	@JsonView(Object.class)
	public Document getScanConfig() {
		return scanConfig;
	}

	public void setScanConfig(Document scanConfig) {
		this.scanConfig = scanConfig;
	}

	@URL(message = "{errors.url}")
	@Size(min = 0, max = 255, message = "{errors.maxlength} " + 255 + ".")
	@JsonView(Object.class)
	public String getTargetUrl() {
		return (targetUrl == null || targetUrl.isEmpty()) && getApplication() != null ? getApplication().getUrl() : targetUrl;
	}

	public void setTargetUrl(String targetUrl) {
		this.targetUrl = targetUrl;
	}

	public void addScanStatus(ScanStatus status) {
		if(this.scanStatuses == null) {
			this.scanStatuses = new ArrayList<ScanStatus>();
		}
		this.scanStatuses.add(status);
	}
	
	public String showStatusString() {

        ScanQueueTaskStatus status = getTaskStatus();

        if (status == null) {
		    return ScanQueueTaskStatus.STATUS_UNKNOWN.getDescription();
        } else {
            return status.getDescription();
        }
	}
	
	/**
	 * Determines if a proposed scanner name is valid. Currently this just checks to make sure that
	 * all of the characters are alphanumeric and that the length is less than 32.
	 * 
	 * TODO - This needs to whitelist-check against a list of known "good" scanner names rather
	 * than just try to avoid riffraff entries.
	 * 
	 * @param proposedScanner proposed scanner name to validate
	 * @return true if the scanner name is valid, false if it is not valid
	 */
	public static boolean validateScanner(String proposedScanner) {
        return (ScannerType.getScannerType(proposedScanner) != null);
	}
	
	/**
	 * Take a scanner type and return the filename for storing that scanner's configuration for
	 * that scan agent.
	 * 
	 * @param scannerType scanner type
	 * @return filename for storing the scan agent configuration for that scanner (returns null if an invalid scanner type is passed in)
	 */
	public static String makeScanAgentConfigFileName(String scannerType) {
		String retVal = null;
		
		if(validateScanner(scannerType)) {
            String sScannerType = ScannerType.getScannerType(scannerType).getShortName();
			retVal = sScannerType + "." + SCANAGENT_CONFIG_FILE_EXTENSION;
		}
		
		return retVal;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
		sb.append("{application.id=");
		sb.append(this.application.getId());
		sb.append(", scanner=");
		sb.append(this.scanner);
		sb.append(", status=");
		sb.append(this.showStatusString());
		sb.append("}");
		
		return sb.toString();
	}
	
	@Transient
	public String getScannerShortName() {
		return ScannerType.getShortName(getScanner());
	}

}
