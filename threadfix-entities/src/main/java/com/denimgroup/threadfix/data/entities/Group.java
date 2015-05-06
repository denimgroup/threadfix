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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.listOf;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 4/29/15.
 */
@Entity
@Table(name = "Groups") // Group is a reserved keyword :(
public class Group extends AuditableEntity implements Iterable<User> {

    private List<User> users;
    private List<AccessControlTeamMap> accessControlTeamMaps;
    private Role globalRole;
    private Boolean hasGlobalAccess = true;
    private String name;

    @ManyToMany(cascade = CascadeType.ALL)
    @JoinTable(name="User_Group",
            joinColumns={ @JoinColumn(name="User_Id") },
            inverseJoinColumns={ @JoinColumn(name="Group_Id") })
    @JsonIgnore
    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }

    @OneToMany(mappedBy = "group")
    @JsonView(AllViews.TableRow.class)
    public List<AccessControlTeamMap> getAccessControlTeamMaps() {
        return accessControlTeamMaps;
    }

    public void setAccessControlTeamMaps(List<AccessControlTeamMap> accessControlTeamMaps) {
        this.accessControlTeamMaps = accessControlTeamMaps;
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

    @Column(length = 255, nullable = false)
    @JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class})
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getHasGlobalAccess() {
        return hasGlobalAccess;
    }

    public void setHasGlobalAccess(Boolean hasGlobalAccess) {
        this.hasGlobalAccess = hasGlobalAccess;
    }

    @JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class})
    @JsonProperty("users")
    @Transient
    public List<Map<?,?>> getUsersJSON() {
        List<Map<?, ?>> users = list();

        if (this.users != null) {
            for (User user : this.users) {
                users.add(map(
                        "name", user.getName(),
                        "id", user.getId()
                ));
            }
        }

        return users;
    }

    @Override
    public Iterator<User> iterator() {
        return users == null ? listOf(User.class).iterator() : users.iterator();
    }
}
