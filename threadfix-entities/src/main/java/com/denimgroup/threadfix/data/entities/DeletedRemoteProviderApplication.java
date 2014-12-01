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

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.Calendar;

@Entity
@Table(name = "DeletedRemoteProviderApplication")
public class DeletedRemoteProviderApplication extends AuditableEntity {

	private static final long serialVersionUID = -7724716111157245914L;

	public DeletedRemoteProviderApplication(RemoteProviderApplication a) {
		if (a != null) {
			setLastImportTime(a.getLastImportTime());
			setNativeId(a.getNativeId());
			setNativeName(a.getNativeName());
			setId(a.getId());

			if (a.getApplicationChannel() != null) {
				setApplicationChannelId(a.getApplicationChannel().getId());
			}

			if (a.getRemoteProviderType() != null) {
				setRemoteProviderTypeId(a.getRemoteProviderType().getId());
			}

			if (a.getApplication() != null) {
				setApplicationId(a.getApplication().getId());
			}
		}
	}
	
	public static final int NATIVE_ID_LENGTH = 1024;

	@Size(max = NATIVE_ID_LENGTH, message = "{errors.maxlength} " + NATIVE_ID_LENGTH + ".")
	private String nativeId;

	public static final int NATIVE_NAME_LENGTH = 1024;

	@Size(max = NATIVE_NAME_LENGTH, message = "{errors.maxlength} " + NATIVE_NAME_LENGTH + ".")
	private String nativeName;
	
	private Integer remoteProviderTypeId, applicationId, applicationChannelId;
	
	private Calendar lastImportTime;

	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getLastImportTime() {
		return lastImportTime;
	}

	public void setLastImportTime(Calendar lastImportTime) {
		this.lastImportTime = lastImportTime;
	}
	
	@Column(length = NATIVE_ID_LENGTH, name = "nativeName")
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}


	@Column(length = NATIVE_NAME_LENGTH, name = "nativeId")
	public String getNativeName() {
		return nativeName;
	}

	public void setNativeName(String nativeName) {
		this.nativeName = nativeName;
	}

	@Column
	public Integer getApplicationId() {
		return applicationId;
	}

	public void setApplicationId(Integer applicationId) {
		this.applicationId = applicationId;
	}

	@Column
	public Integer getRemoteProviderTypeId() {
		return remoteProviderTypeId;
	}

	public void setRemoteProviderTypeId(Integer remoteProviderTypeId) {
		this.remoteProviderTypeId = remoteProviderTypeId;
	}

	@Column
	public Integer getApplicationChannelId() {
		return applicationChannelId;
	}

	public void setApplicationChannelId(Integer applicationChannelId) {
		this.applicationChannelId = applicationChannelId;
	}
	
}
