package com.denimgroup.threadfix.data.entities;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Size;

@Entity
@Table(name = "StaticPathInformation")
public class StaticPathInformation extends AuditableEntity {
	
	public static final String SPRING_MVC_TYPE = "Spring Method Mapping";

	private static final long serialVersionUID = -5267609483088819614L;

	public static final int 
		NAME_LENGTH = 250,
		TYPE_LENGTH = 250,
		VALUE_LENGTH = 250;
	
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;
	
	@Size(max = TYPE_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String type;
	
	@Size(max = VALUE_LENGTH, message = "{errors.maxlength} " + VALUE_LENGTH + ".")
	private String value;

	@Column(length = VALUE_LENGTH)
	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	@Column(length = NAME_LENGTH)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = TYPE_LENGTH)
	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
	
	@Transient
	public String toString() {
		return name + " - " + value;
	}
}
