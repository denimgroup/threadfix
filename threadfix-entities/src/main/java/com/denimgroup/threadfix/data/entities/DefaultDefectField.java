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