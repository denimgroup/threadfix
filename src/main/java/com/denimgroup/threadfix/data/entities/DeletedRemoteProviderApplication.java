package com.denimgroup.threadfix.data.entities;

import java.util.Calendar;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.Size;

@Entity
@Table(name = "DeletedRemoteProviderApplication")
public class DeletedRemoteProviderApplication extends AuditableEntity {

	private static final long serialVersionUID = -7724716111157245914L;

	public DeletedRemoteProviderApplication(RemoteProviderApplication a) {
		if (a != null) {
			setLastImportTime(a.getLastImportTime());
			setNativeId(a.getNativeId());
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
	
	private Integer remoteProviderTypeId, applicationId, applicationChannelId;
	
	private Calendar lastImportTime;

	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getLastImportTime() {
		return lastImportTime;
	}

	public void setLastImportTime(Calendar lastImportTime) {
		this.lastImportTime = lastImportTime;
	}
	
	@Column(length = NATIVE_ID_LENGTH)
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
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
