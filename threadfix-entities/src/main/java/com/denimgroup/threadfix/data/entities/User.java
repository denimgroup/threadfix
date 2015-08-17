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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

@Entity
@Table(name = "User")
public class User extends AuditableEntity {

	private static final long serialVersionUID = -5821877436246475858L;
	
	public static final int NAME_LENGTH = 40;
	public static final int PASSWORD_LENGTH = 256;

	private String name;
	private String displayName;
	private String password;
	private String salt;
	private boolean approved = true;
	private boolean locked = false;
	private Boolean isLdapUser = false;
	private boolean wasLdapUser = false;

	private Boolean hasGlobalGroupAccess = false;
	private Boolean hasChangedInitialPassword = false;
	private Date lastLoginDate = new Date();
	private Date lastPasswordChangedDate = new Date();
	private int failedPasswordAttempts = 0;
	private Date failedPasswordAttemptWindowStart = new Date();

	private String unencryptedPassword;
	private String passwordConfirm;
	private String currentPassword;

	private Role globalRole;

    private List<AccessControlTeamMap> accessControlTeamMaps;
    private List<Group> groups;

    private List<Event> events;
    private List<UserEventNotificationMap> userEventNotificationMaps;

    private List<APIKey> apiKeys;

    @Column(length = NAME_LENGTH, nullable = false)
    @JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class})
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Column(length = PASSWORD_LENGTH, nullable = false)
    @JsonIgnore
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Column(length = PASSWORD_LENGTH, nullable = false)
    @JsonIgnore
    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    @Column(nullable = false)
    @JsonIgnore
    public boolean isApproved() {
        return approved;
    }

    public void setApproved(boolean approved) {
        this.approved = approved;
    }

    @Column(nullable = false)
    @JsonIgnore
    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    @Temporal(TemporalType.TIMESTAMP)
    @Column(nullable = false)
    @JsonIgnore
    public Date getLastPasswordChangedDate() {
        return lastPasswordChangedDate;
    }

    public void setLastPasswordChangedDate(Date lastPasswordChangedDate) {
        this.lastPasswordChangedDate = lastPasswordChangedDate;
    }

    @Temporal(TemporalType.TIMESTAMP)
    @Column(nullable = false)
    @JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class})
    public Date getLastLoginDate() {
        return lastLoginDate;
    }

    public void setLastLoginDate(Date lastLoginDate) {
        this.lastLoginDate = lastLoginDate;
    }

    @Column(nullable = false)
    @JsonIgnore
    public int getFailedPasswordAttempts() {
        return failedPasswordAttempts;
    }

    public void setFailedPasswordAttempts(int failedPasswordAttempts) {
        this.failedPasswordAttempts = failedPasswordAttempts;
    }

    @Temporal(TemporalType.TIMESTAMP)
    @Column(nullable = false)
    @JsonIgnore
    public Date getFailedPasswordAttemptWindowStart() {
        return failedPasswordAttemptWindowStart;
    }

    public void setFailedPasswordAttemptWindowStart(Date failedPasswordAttemptWindowStart) {
        this.failedPasswordAttemptWindowStart = failedPasswordAttemptWindowStart;
    }

    @Transient
    @JsonIgnore
    public String getUnencryptedPassword() {
        return unencryptedPassword;
    }

    public void setUnencryptedPassword(String unencryptedPassword) {
        this.unencryptedPassword = unencryptedPassword;
    }

    @Transient
    @JsonIgnore
    public String getPasswordConfirm() {
        return passwordConfirm;
    }

	public void setPasswordConfirm(String passwordConfirm) {
		this.passwordConfirm = passwordConfirm;
	}

	@Transient
    @JsonIgnore
    public String getCurrentPassword() {
		return currentPassword;
	}

	public void setCurrentPassword(String currentPassword) {
		this.currentPassword = currentPassword;
	}

	//Hibernate naming conventions make this nasty although there may be a good way to do it
	@Column
    @JsonIgnore
	public Boolean isHasChangedInitialPassword() {
		return hasChangedInitialPassword;
	}

	public void setHasChangedInitialPassword(Boolean hasChangedInitialPassword) {
		this.hasChangedInitialPassword = hasChangedInitialPassword;
	}

	@Column
    @JsonView(AllViews.TableRow.class)
	public Boolean getHasGlobalGroupAccess() {
		return hasGlobalGroupAccess != null && hasGlobalGroupAccess;
	}

	public void setHasGlobalGroupAccess(Boolean hasGlobalGroupAccess) {
		this.hasGlobalGroupAccess = hasGlobalGroupAccess;
	}

	@ManyToOne
    @JoinColumn(name = "roleId", nullable = true)
    @JsonView(AllViews.TableRow.class)
    public Role getGlobalRole() {
		return globalRole;
	}

	public void setGlobalRole(Role globalRole) {
		this.globalRole = globalRole;
	}
	
	@OneToMany(mappedBy = "user")
	@JsonIgnore
	public List<AccessControlTeamMap> getAccessControlTeamMaps() {
		return accessControlTeamMaps;
	}

	public void setAccessControlTeamMaps(List<AccessControlTeamMap> accessControlTeamMaps) {
		this.accessControlTeamMaps = accessControlTeamMaps;
	}

    @OneToMany(mappedBy = "user")
    @JsonView(AllViews.TableRow.class)
    public List<APIKey> getApiKeys() {
        return apiKeys;
    }

    public void setApiKeys(List<APIKey> apiKeys) {
        this.apiKeys = apiKeys;
    }

    @Column(nullable = true)
    @JsonView(AllViews.TableRow.class)
	public Boolean getIsLdapUser() {
		return isLdapUser != null && isLdapUser;
	}

	public void setIsLdapUser(Boolean isLdapUser) {
		this.isLdapUser = isLdapUser;
	}

    @Column(length = PASSWORD_LENGTH, nullable = true)
    @JsonView(AllViews.TableRow.class)
    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    @ManyToMany(mappedBy = "users")
    @JsonIgnore
    public List<Group> getGroups() {
        return groups;
    }

    public void setGroups(List<Group> groups) {
        this.groups = groups;
    }

    @OneToMany(mappedBy = "user")
    @OrderBy("date ASC")
    @JsonIgnore
    public List<Event> getEvents() {
        return events;
    }

    public void setEvents(List<Event> events) {
        this.events = events;
    }

    @Transient
    @JsonView({AllViews.UserHistoryView.class})
    public List<Event> getUserEvents() {
        List<Event> userEvents = list();
        for (Event event : getEvents()) {
            if (event.getEventActionEnum().isUserEventAction()) {
                userEvents.add(event);
            }
        }
        return userEvents;
    }

    @OneToMany(mappedBy = "user")
    @JsonIgnore
    public List<UserEventNotificationMap> getUserEventNotificationMaps() {
        return userEventNotificationMaps;
    }

    public void setUserEventNotificationMaps(List<UserEventNotificationMap> userEventNotificationMaps) {
        this.userEventNotificationMaps = userEventNotificationMaps;
    }

    @Transient
    @JsonView(AllViews.TableRow.class)
	public boolean getIsDeletable() {
		return deletable;
	}

	public void setIsDeletable(boolean deletable) {
		this.deletable = deletable;
	}

	@Transient
	public boolean getIsThisUser() {
		return isThisUser;
	}
	
	public void setIsThisUser(boolean isThisUser) {
		this.isThisUser = isThisUser;
	}
	
	@Transient
	public boolean getWasLdap(){
		return wasLdapUser;
	}
	
	public void setWasLdapUser(boolean wasLdapUser){
		this.wasLdapUser = wasLdapUser;
	}

	private boolean deletable, isThisUser;

    @Transient
    @JsonProperty("bestName")
    public String getBestName() {
        return displayName == null || displayName.isEmpty() ? name : displayName;
    }

    @Transient
    @JsonProperty("groups")
    @JsonView(AllViews.TableRow.class)
    public List<?> getGroupsJSON() {
        List<Map<?, ?>> users = list();

        if (this.groups != null) {
            for (Group group : this.groups) {
                users.add(map(
                        "name", group.getName(),
                        "id", group.getId()
                ));
            }
        }

        return users;
    }
    @Transient
    @JsonProperty("accessControlTeamMaps")
    @JsonView(AllViews.TableRow.class)
    public List<?> getAccessControlTeamMapsJSON() {
        List<Map<?, ?>> teamMaps = list();

        if (this.accessControlTeamMaps != null) {
            for (AccessControlTeamMap accessControlTeamMap : this.accessControlTeamMaps) {

                List<Map<?, ?>> appMaps = list();

                for (AccessControlApplicationMap appMap : accessControlTeamMap.getAccessControlApplicationMaps()) {
                    appMaps.add(map(
                                    "teamName", accessControlTeamMap.getOrganization().getName(),
                                    "roleName", appMap.getRole() != null ? appMap.getRole().getDisplayName() : "-",
                                    "appName", appMap.getApplication().getName()
                            )
                    );
                }

                teamMaps.add(map(
                        "roleName", accessControlTeamMap.getRole() != null ? accessControlTeamMap.getRole().getDisplayName() : "-",
                        "teamName", accessControlTeamMap.getOrganization().getName(),
                        "appRoles", appMaps
                    )
                );
            }
        }

        return teamMaps;
    }


}
