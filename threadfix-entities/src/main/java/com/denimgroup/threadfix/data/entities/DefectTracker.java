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

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.validator.constraints.NotEmpty;
import org.hibernate.validator.constraints.URL;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

@Entity
@Table(name = "DefectTracker")
public class DefectTracker extends AuditableEntity {

	private static final long serialVersionUID = 1135227457979044959L;
	
	public final static int NAME_LENGTH = 50;
	public final static int URL_LENGTH = 255;
    public final static int DEFAULT_USERNAME_LENGTH = 50;
    public final static int DEFAULT_PASSWORD_LENGTH = 50;
    public final static int ENCRYPTED_DEFAULT_USERNAME_LENGTH = 1024;
    public final static int ENCRYPTED_DEFAULT_PASSWORD_LENGTH = 1024;
    public final static int DEFAULT_PRODUCT_NAME_LENGTH = 50;

	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;

	@URL(message = "{errors.url}")
	@NotEmpty(message = "{errors.required}")
	@Size(max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
	private String url;

    @Size(max = DEFAULT_USERNAME_LENGTH, message = "{errors.maxlength} " + DEFAULT_USERNAME_LENGTH + ".")
    private String defaultUsername;

    @Size(max = ENCRYPTED_DEFAULT_USERNAME_LENGTH, message = "{errors.maxlength} " + ENCRYPTED_DEFAULT_USERNAME_LENGTH + ".")
    private String encryptedDefaultUsername;

    @Size(max = DEFAULT_PASSWORD_LENGTH, message = "{errors.maxlength} " + DEFAULT_PASSWORD_LENGTH + ".")
    private String defaultPassword;

    @Size(max = ENCRYPTED_DEFAULT_PASSWORD_LENGTH, message = "{errors.maxlength} " + ENCRYPTED_DEFAULT_PASSWORD_LENGTH + ".")
    private String encryptedDefaultPassword;

    @Size(max = DEFAULT_PRODUCT_NAME_LENGTH, message = "{errors.maxlength} " + DEFAULT_PRODUCT_NAME_LENGTH + ".")
    private String defaultProductName;

	private DefectTrackerType defectTrackerType;
	private List<Application> applications;
	private List<DefaultDefectProfile> defaultDefectProfiles;

	@Column(length = NAME_LENGTH)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = URL_LENGTH)
    @JsonView(Object.class)
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

    @Transient
    @JsonView({ AllViews.DefectTrackerInfos.class, AllViews.FormInfo.class })
    public String getDefaultUsername() {
        return defaultUsername;
    }

    public void setDefaultUsername(String defaultUsername) {
        this.defaultUsername = defaultUsername;
    }

    @Transient
    @JsonView({ AllViews.DefectTrackerInfos.class, AllViews.FormInfo.class })
    public String getDefaultPassword() {
        return defaultPassword;
    }

    public void setDefaultPassword(String defaultPassword) {
        this.defaultPassword = defaultPassword;
    }

    @Column(length = ENCRYPTED_DEFAULT_USERNAME_LENGTH)
    @JsonIgnore
    public String getEncryptedDefaultUsername() {
        return encryptedDefaultUsername;
    }

    public void setEncryptedDefaultUsername(String encryptedDefaultUsername) {
        this.encryptedDefaultUsername = encryptedDefaultUsername;
    }

    @Column(length = ENCRYPTED_DEFAULT_PASSWORD_LENGTH)
    @JsonIgnore
    public String getEncryptedDefaultPassword() {
        return encryptedDefaultPassword;
    }

    public void setEncryptedDefaultPassword(String encryptedDefaultPassword) {
        this.encryptedDefaultPassword = encryptedDefaultPassword;
    }

    @Column(length = DEFAULT_PRODUCT_NAME_LENGTH)
    @JsonView({ AllViews.DefectTrackerInfos.class, AllViews.FormInfo.class })
    public String getDefaultProductName() {
        return defaultProductName;
    }

    public void setDefaultProductName(String defaultProductName) {
        this.defaultProductName = defaultProductName;
    }

    @ManyToOne
	@JoinColumn(name = "defectTrackerTypeId")
    @JsonView(Object.class)
    public DefectTrackerType getDefectTrackerType() {
		return defectTrackerType;
	}

	public void setDefectTrackerType(DefectTrackerType defectTrackerType) {
		this.defectTrackerType = defectTrackerType;
	}

	@OneToMany
	@JoinColumn(name = "defectTrackerId")
	@JsonView({AllViews.DefectTrackerInfos.class})
	public List<Application> getApplications() {
		return applications;
	}

	public void setApplications(List<Application> applications) {
		this.applications = applications;
	}

	@JsonView({ AllViews.DefectTrackerInfos.class, AllViews.FormInfo.class })
	@OneToMany(mappedBy = "defectTracker", cascade = CascadeType.ALL)
	public List<DefaultDefectProfile> getDefaultDefectProfiles() {
		return defaultDefectProfiles;
	}

	public void setDefaultDefectProfiles(List<DefaultDefectProfile> defaultDefectProfiles) {
		this.defaultDefectProfiles = defaultDefectProfiles;
	}

	@Transient
	@JsonIgnore
	public String getDisplayName() {
		return this.toString();
	}

	@Override
	@Transient
	public String toString() {
		String displayName = name;
		if (defectTrackerType != null) {
			displayName += " (" + defectTrackerType.getName() + ")";
		}
		return displayName;
	}

	@Transient
	@JsonView({AllViews.FormInfo.class})
	public List<Map> getAssociatedApplications() {
		List<Map> apps = list();
		if (applications != null) {
			for (Application application: applications) {
				apps.add(map("id", application.getId(), "name", application.getName(), "team", application.getTeam()));
			}
		}
		return apps;
	}
	
}
