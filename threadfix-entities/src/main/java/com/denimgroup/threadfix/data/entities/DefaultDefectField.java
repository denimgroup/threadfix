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

import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.annotations.CollectionOfElements;

import javax.persistence.*;
import java.util.Map;

@Entity
@Table(name = "DefaultDefectField")
public class DefaultDefectField extends AuditableEntity {

	private static final long serialVersionUID = -8901175337133794868L;

	private String fieldName;
	private String staticValue;
	private String dynamicValue;
	private boolean dynamicDefault;
	private boolean valueMapping;

	private DefaultTag defaultTag;
	private DefaultDefectProfile DefaultDefectProfile;

	private Map<String,String> valueMappingMap;

	//here we declare through the JPA API a table that will hold the key-value pairs of our Map,
	//we do this because strings are basic types so we don't have to declare an entity
	@JsonView(Object.class)
	@CollectionOfElements // for sonar
	@ElementCollection
	@MapKeyColumn(name = "keyValue", length = 128)
	@Column(name = "defaultValue", length = 128)
	@CollectionTable(name = "DefaultValueMappingMap", joinColumns = @JoinColumn(name = "defaultDefectFieldId"))
	public Map<String,String> getValueMappingMap() {
		return valueMappingMap;
	}

	public void setValueMappingMap(Map<String,String> valueMappingMap) {
		this.valueMappingMap = valueMappingMap;
	}

	@Column
	@JsonView(Object.class)
	public String getFieldName() {
		return fieldName;
	}

	public void setFieldName(String fieldName) {
		this.fieldName = fieldName;
	}

	@Column
	@JsonView(Object.class)
	public String getStaticValue() {
		return staticValue;
	}

	public void setStaticValue(String staticValue) {
		this.staticValue = staticValue;
	}

	@Column
	@JsonView(Object.class)
	public String getDynamicValue() {
		return dynamicValue;
	}

	public void setDynamicValue(String dynamicValue) {
		this.dynamicValue = dynamicValue;
	}

	@Column(nullable = false)
	@JsonView(Object.class)
	public boolean isDynamicDefault() {
		return dynamicDefault;
	}

	public void setDynamicDefault(boolean dynamicDefault) {
		this.dynamicDefault = dynamicDefault;
	}

	@Column(nullable = false)
	@JsonView(Object.class)
	public boolean isValueMapping() {
		return valueMapping;
	}

	public void setValueMapping(boolean valueMapping) {
		this.valueMapping = valueMapping;
	}

	@ManyToOne
	@JoinColumn(name = "defaultDefectProfileId")
	public DefaultDefectProfile getDefaultDefectProfile() {
		return DefaultDefectProfile;
	}

	public void setDefaultDefectProfile(DefaultDefectProfile defaultDefectProfile) {
		DefaultDefectProfile = defaultDefectProfile;
	}

	@ManyToOne
	@JoinColumn(name = "defaultTagId")
	@JsonView(Object.class)
	public DefaultTag getDefaultTag() {
		return defaultTag;
	}

	public void setDefaultTag(DefaultTag defaultTag) {
		this.defaultTag = defaultTag;
	}
}