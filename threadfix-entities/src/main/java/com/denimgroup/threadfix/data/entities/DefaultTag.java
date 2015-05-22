package com.denimgroup.threadfix.data.entities;

import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "DefaultTag")
public class DefaultTag extends BaseEntity {

	private static final long serialVersionUID = 885142349584518637L;

	private String name;
	private String fullClassName;
	private String description;

	@Column(length = 25, nullable = false, unique = true)
	@JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length=512, nullable = false)
	public String getFullClassName() {
		return fullClassName;
	}

	public void setFullClassName(String fullClassName) {
		this.fullClassName = fullClassName;
	}

	@Column(length = 2000)
	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}
}
