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

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonView;

import javax.persistence.*;

/**
 * Created by mac on 11/20/14.
 */
@Entity
@Table(name = "RemoteProviderAuthenticationField")
public class RemoteProviderAuthenticationField extends BaseEntity {

    String name, value;

    boolean secret = false;

    RemoteProviderType remoteProviderType;

    @Column
    @JsonView(Object.class)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Column(length = 1024)
    @JsonView(Object.class)
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Column
    @JsonView(Object.class)
    public boolean isSecret() {
        return secret;
    }

    public void setSecret(boolean secret) {
        this.secret = secret;
    }

    @ManyToOne
    @JoinColumn(name = "applicationId")
    @JsonIgnore
    public RemoteProviderType getRemoteProviderType() {
        return remoteProviderType;
    }

    public void setRemoteProviderType(RemoteProviderType remoteProviderType) {
        this.remoteProviderType = remoteProviderType;
    }

}
