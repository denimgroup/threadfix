package com.denimgroup.threadfix.data.entities;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.constraints.Size;

@Entity
@Table(name = "RemoteProviderApplication")
public class RemoteProviderApplication extends BaseEntity  {
	
	private static final long serialVersionUID = 5023873433359926246L;

	// Veracode Build numbers / whatever WhiteHat has.
	// TODO checking on this
	public static final int NATIVE_ID_LENGTH = 50;

	@Size(max = NATIVE_ID_LENGTH, message = "{errors.maxlength} " + NATIVE_ID_LENGTH + ".")
	public String nativeId;
	
	public RemoteProviderType remoteProviderType;
	
	public Application application;
	public ApplicationChannel applicationChannel;

	@Column(length = NATIVE_ID_LENGTH)
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}

	@ManyToOne
	@JoinColumn(name = "remoteProviderTypeId")
	public RemoteProviderType getRemoteProviderType() {
		return remoteProviderType;
	}

	public void setRemoteProviderType(RemoteProviderType remoteProviderType) {
		this.remoteProviderType = remoteProviderType;
	}

	@ManyToOne
	@JoinColumn(name = "applicationId")
	public Application getApplication() {
		return application;
	}

	public void setApplication(Application application) {
		this.application = application;
	}

	@OneToOne
	public ApplicationChannel getApplicationChannel() {
		return applicationChannel;
	}
	
	public void setApplicationChannel(ApplicationChannel applicationChannel) {
		this.applicationChannel = applicationChannel;
	}
	
}
