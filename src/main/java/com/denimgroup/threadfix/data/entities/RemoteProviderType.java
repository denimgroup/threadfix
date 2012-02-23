package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "RemoteProviderType")
public class RemoteProviderType extends BaseEntity  {
	
	private static final long serialVersionUID = -4542241524388720916L;
	
	public static final String SENTINEL = ChannelType.SENTINEL;
	public static final String VERACODE = ChannelType.VERACODE;

	public static final int NAME_LENGTH = 60;
	public static final int API_KEY_LENGTH = 200;
	
	// TODO Check actual limits (Veracode right now) and use those
	public static final int USERNAME_LENGTH = 100;
	public static final int PASSWORD_LENGTH = 100;

	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	public String name;
	
	public boolean hasApiKey;
	
	@Size(max = API_KEY_LENGTH, message = "{errors.maxlength} " + API_KEY_LENGTH + ".")
	public String apiKeyString;
	
	public boolean hasUserNamePassword;
	
	@Size(max = API_KEY_LENGTH, message = "{errors.maxlength} " + API_KEY_LENGTH + ".")
	public String username;
	@Size(max = API_KEY_LENGTH, message = "{errors.maxlength} " + API_KEY_LENGTH + ".")
	public String password;
	
	public List<RemoteProviderApplication> remoteProviderApplications;
	public ChannelType channelType;
	
	@Column(nullable = false)
	public boolean hasApiKey() {
		return hasApiKey;
	}

	public void setHasApiKey(boolean hasApiKey) {
		this.hasApiKey = hasApiKey;
	}

	@Column(length = API_KEY_LENGTH)
	public String getApiKeyString() {
		return apiKeyString;
	}

	public void setApiKeyString(String apiKeyString) {
		this.apiKeyString = apiKeyString;
	}

	@Column(nullable = false)
	public boolean hasUserNamePassword() {
		return hasUserNamePassword;
	}
	
	public void setHasUserNamePassword(boolean hasUserNamePassword) {
		this.hasUserNamePassword = hasUserNamePassword;
	}

	@Column(length = USERNAME_LENGTH)
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Column(length = PASSWORD_LENGTH)
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@ManyToOne
	@JoinColumn(name = "channelTypeId")
	@JsonIgnore
	public ChannelType getChannelType() {
		return channelType;
	}

	public void setChannelType(ChannelType channelType) {
		this.channelType = channelType;
	}

	@Column(length = NAME_LENGTH)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@OneToMany(mappedBy = "remoteProviderType")
	public List<RemoteProviderApplication> getRemoteProviderApplications() {
		return remoteProviderApplications;
	}

	public void setRemoteProviderApplications(
			List<RemoteProviderApplication> remoteProviderApplications) {
		this.remoteProviderApplications = remoteProviderApplications;
	}
}
