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

/**
 * @author zabdisubhan
 *
 */
@Entity
@Table(name = "GRCTool")
public class GRCTool extends AuditableEntity {

    private static final long serialVersionUID = 8519166458033435323L;

    public final static int NAME_LENGTH = 60;
    public final static int URL_LENGTH = 255;
    public static final int USERNAME_LENGTH = 1024;
    public static final int PASSWORD_LENGTH = 1024;

    @NotEmpty(message = "{errors.required}")
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    private String name;

    @URL(message = "{errors.url}")
    @NotEmpty(message = "{errors.required}")
    @Size(max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
    private String url;

    private GRCToolType grcToolType;
    private List<GRCApplication> grcApplications;

    @Size(max = USERNAME_LENGTH, message = "{errors.maxlength} " + USERNAME_LENGTH + ".")
    private String encryptedUsername;
    @Size(max = PASSWORD_LENGTH, message = "{errors.maxlength} " + PASSWORD_LENGTH + ".")
    private String encryptedPassword;
    @Size(max = 60, message = "{errors.maxlength} " + 60 + ".")
    private String username;
    @Size(max = 60, message = "{errors.maxlength} " + 60 + ".")
    private String password;

    @Column(length = NAME_LENGTH, unique=true)
    @JsonView(Object.class)
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
    @JoinColumn(name = "grcToolTypeId")
    @JsonView(Object.class)
    public GRCToolType getGrcToolType() {
        return grcToolType;
    }

    public void setGrcToolType(GRCToolType grcToolType) {
        this.grcToolType = grcToolType;
    }

    @OneToMany(mappedBy = "grcTool", cascade = CascadeType.ALL)
    @JsonView(Object.class)
    public List<GRCApplication> getGrcApplications() {
        return grcApplications;
    }

    public void setGrcApplications(List<GRCApplication> grcApplications) {
        this.grcApplications = grcApplications;
    }

    @Override
    @Transient
    public String toString() {
        String displayName = name;
        if (grcToolType != null) {
            displayName += " (" + grcToolType.getName() + ")";
        }
        return displayName;
    }
}