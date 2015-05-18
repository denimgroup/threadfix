package com.denimgroup.threadfix.data.entities;

import java.util.Map;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.MapKeyColumn;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonView;

@Entity
@Table(name = "DefaultDefectField")
public class DefaultDefectField extends AuditableEntity {

	private static final long serialVersionUID = -8901175337133794868L;

	private String fieldName;
	private String staticValue;
	private boolean dynamicDefault;
	private boolean valueMapping;

	private DefaultTag defaultTag;
	private DefaultDefectProfile DefaultDefectProfile;

	private Map<String,String> valueMappingMap;

	//here we declare through the JPA API a table that will hold the key-value pairs of our Map,
	//we do this because strings are basic types so we don't have to declare an entity
	@JsonView(Object.class)
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