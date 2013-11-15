package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "RemoteProviderType")
public class RemoteProviderType extends BaseEntity  {
	
	private static final long serialVersionUID = -4542241524388720916L;
	
	public static final String SENTINEL = ScannerType.SENTINEL.getFullName();
	public static final String VERACODE = ScannerType.VERACODE.getFullName();
	public static final String QUALYSGUARD_WAS = ScannerType.QUALYSGUARD_WAS.getFullName();

	public static final int NAME_LENGTH = 60;
	public static final int API_KEY_LENGTH = 1024;
	
	// TODO Check actual limits (Veracode right now) and use those
	public static final int USERNAME_LENGTH = 1024;
	public static final int PASSWORD_LENGTH = 1024;
	//No components were found for the configured Defect Tracker project.
	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;
	
	private boolean hasApiKey;
	
	// TODO normalize this if it becomes more than a one-off thing (RP Region table or similar)
	private boolean isEuropean = false;
	
	private boolean encrypted = false;
	
	@Size(max = API_KEY_LENGTH, message = "{errors.maxlength} " + API_KEY_LENGTH + ".")
	private String encryptedApiKey;
	
	private boolean hasUserNamePassword;
	
	@Size(max = USERNAME_LENGTH, message = "{errors.maxlength} " + USERNAME_LENGTH + ".")
	private String encryptedUsername;
	@Size(max = PASSWORD_LENGTH, message = "{errors.maxlength} " + PASSWORD_LENGTH + ".")
	private String encryptedPassword;
	@Size(max = 60, message = "{errors.maxlength} " + 60 + ".")
	private String username;
	@Size(max = 60, message = "{errors.maxlength} " + 60 + ".")
	private String password;
	@Size(max = 100, message = "{errors.maxlength} " + 100 + ".")
	private String apiKey;
	
	private List<RemoteProviderApplication> remoteProviderApplications;
	private List<RemoteProviderApplication> filteredApplications;
	private ChannelType channelType;

	@Transient
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Transient
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Transient
	public String getApiKey() {
		return apiKey;
	}

	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}
	
	@Column(nullable = false)
	public boolean getHasApiKey() {
		return hasApiKey;
	}

	public void setHasApiKey(boolean hasApiKey) {
		this.hasApiKey = hasApiKey;
	}

	@Column(length = API_KEY_LENGTH)
	public String getEncryptedApiKey() {
		return encryptedApiKey;
	}

	public void setEncryptedApiKey(String encryptedApiKey) {
		this.encryptedApiKey = encryptedApiKey;
	}

	@Column(nullable = false)
	public boolean getHasUserNamePassword() {
		return hasUserNamePassword;
	}
	
	public void setHasUserNamePassword(boolean hasUserNamePassword) {
		this.hasUserNamePassword = hasUserNamePassword;
	}

	@Column(length = USERNAME_LENGTH)
	public String getEncryptedUsername() {
		return encryptedUsername;
	}

	public void setEncryptedUsername(String encryptedUsername) {
		this.encryptedUsername = encryptedUsername;
	}

	@Column(length = PASSWORD_LENGTH)
	public String getEncryptedPassword() {
		return encryptedPassword;
	}

	public void setEncryptedPassword(String encryptedPassword) {
		this.encryptedPassword = encryptedPassword;
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
	
	public String toString() {
		return name;
	}

	@OneToMany(mappedBy = "remoteProviderType")
	public List<RemoteProviderApplication> getRemoteProviderApplications() {
		return remoteProviderApplications;
	}

	/**
	 * Sort whenever a new collection is set.
	 * @param remoteProviderApplications
	 */
	public void setRemoteProviderApplications(
			List<RemoteProviderApplication> remoteProviderApplications) {
		this.remoteProviderApplications = remoteProviderApplications;
	}

	public boolean isEncrypted() {
		return encrypted;
	}

	public void setEncrypted(boolean encrypted) {
		this.encrypted = encrypted;
	}

	// These have clunky names to make Hibernate happy.
	public boolean getIsEuropean() {
		return isEuropean;
	}

	public void setIsEuropean(boolean isEuropean) {
		this.isEuropean = isEuropean;
	}

	@Transient
	public List<RemoteProviderApplication> getFilteredApplications() {
		return filteredApplications;
	}

	public void setFilteredApplications(List<RemoteProviderApplication> filteredApplications) {
		this.filteredApplications = filteredApplications;
	}
	
	@Transient
	public boolean getIsQualys() {
		return name != null && name.equals(QUALYSGUARD_WAS);
	}
	
	@Transient
	public boolean getHasConfiguredApplications() {
		boolean hasAppsWithApps = false;
		
		if (remoteProviderApplications != null && !remoteProviderApplications.isEmpty()) {
			for (RemoteProviderApplication app : getRemoteProviderApplications()) {
				if (app != null && app.getApplicationChannel() != null) {
					hasAppsWithApps = true;
					break;
				}
			}
		}
		
		return hasAppsWithApps;
	}
}
