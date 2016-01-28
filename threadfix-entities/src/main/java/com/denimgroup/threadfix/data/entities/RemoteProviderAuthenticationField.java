////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 11/20/14.
 */
@Entity
@Table(name = "RemoteProviderAuthenticationField")
public class RemoteProviderAuthenticationField extends BaseEntity {

    String name, value, encryptedValue, placeholder, type;

    Boolean secret = false, required = false;

    RemoteProviderType remoteProviderType;

    List<SelectOption> selectOptions = list();

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

    @Column(length = 255)
    @JsonView(Object.class)
    public String getPlaceholder() {
        return placeholder;
    }

    public void setPlaceholder(String placeholder) {
        this.placeholder = placeholder;
    }

    @Column(length = 255)
    @JsonView(Object.class)
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @Column
    @JsonView(Object.class)
    public Boolean isSecret() {
        return secret;
    }

    public void setSecret(Boolean secret) {
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

    @Column(length = 1024)
    @JsonIgnore
    public String getEncryptedValue() {
        return encryptedValue;
    }

    public void setEncryptedValue(String encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    @Column
    @JsonView(Object.class)
    public Boolean getRequired() {
        return required;
    }

    public void setRequired(Boolean required) {
        this.required = required;
    }

    public Boolean getSecret() {
        return secret;
    }

    @JsonView(Object.class)
    @OneToMany(cascade = CascadeType.ALL)
    public List<SelectOption> getSelectOptions() {
        return selectOptions;
    }

    public void setSelectOptions(List<SelectOption> selectOptions) {
        this.selectOptions = selectOptions;
    }
}
