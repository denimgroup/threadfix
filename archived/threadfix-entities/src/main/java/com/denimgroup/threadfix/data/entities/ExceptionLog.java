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

import com.denimgroup.threadfix.DiskUtils;

import javax.persistence.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Calendar;

@Entity
@Table(name = "ExceptionLog")
public final class ExceptionLog extends BaseEntity {

	private static final long serialVersionUID = 5149357883041480368L;

	private String exceptionStackTrace;
	private Calendar time;

	private String commit;
	
	private String exceptionToString;
	private String message;
	private String uuid;
	private String type;

	private Long totalSpaceAvailable = null, freeMemory = null, totalMemoryAvailable = null;
	
	/**
	 * This is to make Spring happy and allow us to retrieve items from the database. 
	 * Use the other one.
	 */
	public ExceptionLog(){}
	
	public ExceptionLog(Throwable e) {
		if (e == null || e.getStackTrace() == null)
			return;
		
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		PrintStream printStream = new PrintStream(byteArrayOutputStream);

		e.printStackTrace(printStream);

		setExceptionStackTrace(byteArrayOutputStream.toString());
		setTime(Calendar.getInstance());
		setMessage(e.getMessage());
		setType(e.getClass().getSimpleName());
		setExceptionToString(e.toString());
		setUUID(java.util.UUID.randomUUID().toString());
		setTotalMemoryAvailable(Runtime.getRuntime().maxMemory());
		setFreeMemory(Runtime.getRuntime().freeMemory());
		setTotalSpaceAvailable(DiskUtils.getAvailableDiskSpace());
		
		if (message != null && message.length() >= 255)
			message = message.substring(0, 254);
		
		try {
			byteArrayOutputStream.close();
			printStream.close();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	@Lob @Column
	public String getExceptionStackTrace() {
		return exceptionStackTrace;
	}

	public void setExceptionStackTrace(String exceptionStackTrace) {
		this.exceptionStackTrace = exceptionStackTrace;
	}
	
	@Column(length = 36)
	public String getUUID() {
		return uuid;
	}
	
	public void setUUID(String uuid) {
		this.uuid = uuid;
	}
	
	@Column(length = 256)
	public String getType() {
		return type;
	}
	
	public void setType(String type) {
		this.type = type;
	}
	
	@Column(length = 512)
	public String getMessage() {
		return message;
	}
	
	public void setMessage(String message) {
		this.message = message;
	}

	@Lob @Column
	public String getExceptionToString() {
		return exceptionToString;
	}
	
	public void setExceptionToString(String exceptionToString) {
		this.exceptionToString = exceptionToString;
	}
	
	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getTime() {
		return time;
	}

	public void setTime(Calendar time) {
		this.time = time;
	}

	@Column(nullable = true)
	public String getCommit() {
		return commit;
	}

	public void setCommit(String commit) {
		this.commit = commit;
	}

	@Column(nullable = true)
	public Long getTotalSpaceAvailable() {
		return totalSpaceAvailable;
	}

	public void setTotalSpaceAvailable(Long totalSpaceAvailable) {
		this.totalSpaceAvailable = totalSpaceAvailable;
	}

	@Column(nullable = true)
	public Long getFreeMemory() {
		return freeMemory;
	}

	public void setFreeMemory(Long freeMemory) {
		this.freeMemory = freeMemory;
	}

	@Column(nullable = true)
	public Long getTotalMemoryAvailable() {
		return totalMemoryAvailable;
	}

	public void setTotalMemoryAvailable(Long totalMemoryAvailable) {
		this.totalMemoryAvailable = totalMemoryAvailable;
	}
}
