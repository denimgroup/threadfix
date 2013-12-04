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

package com.denimgroup.threadfix.data.entities;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.annotations.Type;

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
	public String getScanner() {
		return this.scanner;
	}
	
	public void setScanner(String scanner) {
		this.scanner = scanner;
	}
	
	@Column
	public String getVersion() {
		return this.version;
	}
	
	public void setVersion(String version) {
		this.version = version;
	}
	
	
	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable=false)
	public Date getCreateTime() {
		return createTime;
	}

	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
	public Date getStartTime() {
		return startTime;
	}

	public void setStartTime(Date startTime) {
		this.startTime = startTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
	public Date getEndTime() {
		return endTime;
	}

	public void setEndTime(Date endTime) {
		this.endTime = endTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
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

	public void addScanStatus(ScanStatus status) {
		if(this.scanStatuses == null) {
			this.scanStatuses = new ArrayList<>();
		}
		this.scanStatuses.add(status);
	}
	
	public String showStatusString() {
		
		for (ScanQueueTaskStatus status : ScanQueueTaskStatus.values()) {
			if (status.getValue() == this.status) {
				return status.getDescription();
			}
		}
		
		return ScanQueueTaskStatus.STATUS_UNKNOWN.getDescription();
		
		
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
//		boolean retVal = false;

        return (ScannerType.getScannerType(proposedScanner) != null);


//		if (proposedScanner != null && proposedScanner.length() <= 32) {
//			boolean foundBadChar = false;
//			for (int i=0; i < proposedScanner.length(); ++i) {
//				if (!Character.isLetterOrDigit(proposedScanner.charAt(i))) {
//					foundBadChar = true;
//					break;
//				}
//			}
//			if(!foundBadChar) {
//				retVal = true;
//			}
//		}
//
//		return retVal;
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
