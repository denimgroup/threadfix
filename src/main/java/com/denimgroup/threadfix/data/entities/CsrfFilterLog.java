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

import java.util.Calendar;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.servlet.http.HttpServletRequest;

@Entity
@Table(name = "CsrfFilterLog")
public class CsrfFilterLog extends BaseEntity {

	private static final long serialVersionUID = 5149357883041480368L;

	private Calendar loggedTime;
	
	private String ip;
	private String url;
	private String status;
	
	public CsrfFilterLog(HttpServletRequest httpServletRequest, String status) {	
		setUrl(httpServletRequest.getRequestURL().toString());
		setIp(httpServletRequest.getRemoteAddr());
		setLoggedTime(Calendar.getInstance());
		
		String trimmedStatus = status;
		if (trimmedStatus != null && trimmedStatus.length() > 1023)
			trimmedStatus = trimmedStatus.substring(0, 1023);
		
		setStatus(trimmedStatus);
	}
	
	@Column(length = 1024)
	public String getUrl() {
		return url;
	}
	
	public void setUrl(String url) {
		this.url = url;
	}
	
	@Column(length = 1024)
	public String getStatus() {
		return status;
	}
	
	public void setStatus(String status) {
		this.status = status;
	}
	
	@Column(length = 25)
	public String getIp() {
		return ip;
	}
	
	public void setIp(String ip) {
		this.ip = ip;
	}
	
	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getLoggedTime() {
		return loggedTime;
	}

	public void setLoggedTime(Calendar loggedTime) {
		this.loggedTime = loggedTime;
	}
}
