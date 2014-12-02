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
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;

@Entity
@Table(name = "RemoteProviderType")
public class RemoteProviderType extends BaseEntity  {

    private static final long serialVersionUID = -4542241524388720916L;

    public static final String SENTINEL        = ScannerType.SENTINEL.getFullName();
    public static final String VERACODE        = ScannerType.VERACODE.getFullName();
    public static final String QUALYSGUARD_WAS = ScannerType.QUALYSGUARD_WAS.getFullName();

    public static final int NAME_LENGTH    = 60;
    public static final int API_KEY_LENGTH = 1024;

    // TODO Check actual limits (Veracode right now) and use those
    public static final int USERNAME_LENGTH = 1024;
    public static final int PASSWORD_LENGTH = 1024;
    //No components were found for the configured Defect Tracker project.
    @NotEmpty(message = "{errors.required}")
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    private String name;

    private boolean hasApiKey;

    private Boolean matchSourceNumbers = false;

    // TODO normalize this if it becomes more than a one-off thing (RP Region table or similar)
    private boolean isEuropean = false;

    private String platform;

    private boolean encrypted = false;

    private List<RemoteProviderAuthenticationField> authenticationFields;

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
    private ChannelType                     channelType;
    private boolean                         matchSourceNumbersNullSafe;

    @Transient
    @JsonView(AllViews.TableRow.class)
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Transient
    @JsonView(AllViews.TableRow.class)
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Transient
    @JsonView(AllViews.TableRow.class)
    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    @Column(nullable = false)
    @JsonView(AllViews.TableRow.class)
    public boolean getHasApiKey() {
        return hasApiKey;
    }

    public void setHasApiKey(boolean hasApiKey) {
        this.hasApiKey = hasApiKey;
    }

    @Column(length = API_KEY_LENGTH)
    @JsonIgnore
    public String getEncryptedApiKey() {
        return encryptedApiKey;
    }

    public void setEncryptedApiKey(String encryptedApiKey) {
        this.encryptedApiKey = encryptedApiKey;
    }

    @Column(nullable = false)
    @JsonView(AllViews.TableRow.class)
    public boolean getHasUserNamePassword() {
        return hasUserNamePassword;
    }

    public void setHasUserNamePassword(boolean hasUserNamePassword) {
        this.hasUserNamePassword = hasUserNamePassword;
    }

    @Column(length = USERNAME_LENGTH)
    @JsonIgnore
    public String getEncryptedUsername() {
        return encryptedUsername;
    }

    public void setEncryptedUsername(String encryptedUsername) {
        this.encryptedUsername = encryptedUsername;
    }

    @Column(length = PASSWORD_LENGTH)
    @JsonIgnore
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
    @JsonView(AllViews.TableRow.class)
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
    @JsonView(AllViews.TableRow.class)
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

    @JsonIgnore
	public boolean isEncrypted() {
		return encrypted;
	}

	public void setEncrypted(boolean encrypted) {
		this.encrypted = encrypted;
	}

    @JsonView(AllViews.TableRow.class)
	public String getPlatform() {
		return platform;
	}

	public void setPlatform(String platform) {
		this.platform = platform;
	}

    // These have clunky names to make Hibernate happy.
    @JsonView(AllViews.TableRow.class)
    public boolean getIsEuropean() {
        return isEuropean;
    }

    public void setIsEuropean(boolean isEuropean) {
        this.isEuropean = isEuropean;
    }

    @JsonView(AllViews.TableRow.class)
    @Column(nullable = true)
    public Boolean getMatchSourceNumbers() {
        return matchSourceNumbers;
    }

    public void setMatchSourceNumbers(Boolean matchSourceNumbers) {
        this.matchSourceNumbers = matchSourceNumbers;
    }

    @OneToMany(mappedBy = "remoteProviderType", cascade = CascadeType.ALL)
    @JsonView(AllViews.TableRow.class)
    public List<RemoteProviderAuthenticationField> getAuthenticationFields() {
        return authenticationFields;
    }

    public void setAuthenticationFields(List<RemoteProviderAuthenticationField> authenticationFields) {
        this.authenticationFields = authenticationFields;
    }

	@Transient
    @JsonView(AllViews.TableRow.class)
	public List<RemoteProviderApplication> getFilteredApplications() {
		return filteredApplications;
	}

	public void setFilteredApplications(List<RemoteProviderApplication> filteredApplications) {
		this.filteredApplications = filteredApplications;
	}

	@Transient
    @JsonView(AllViews.TableRow.class)
	public boolean getIsQualys() {
		return name != null && name.equals(QUALYSGUARD_WAS);
	}

	@Transient
    @JsonView(AllViews.TableRow.class)
	public boolean getIsWhiteHat() {
		return name != null && name.equals(SENTINEL);
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

    @Transient
    public boolean getMatchSourceNumbersNullSafe() {
        return matchSourceNumbers != null && matchSourceNumbers;
    }
}
