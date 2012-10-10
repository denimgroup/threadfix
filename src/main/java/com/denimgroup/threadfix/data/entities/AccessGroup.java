package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name="AccessGroup")
public class AccessGroup extends AuditableEntity {

	private static final long serialVersionUID = 4178405361830192662L;
	public static final int NAME_LENGTH = 255;

	private List<AccessGroup> childGroups;
	private AccessGroup parentGroup;
	private Organization team;
	private List<UserGroupMap> userGroupMaps;
	
	private String name;
	
	@OneToMany(mappedBy = "accessGroup")
	@JsonIgnore
	public List<UserGroupMap> getUserGroupMaps() {
		return userGroupMaps;
	}

	public void setUserGroupMaps(List<UserGroupMap> userGroupMaps) {
		this.userGroupMaps = userGroupMaps;
	}

	@Column(length=NAME_LENGTH)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@ManyToOne
	@JoinColumn(name = "parentGroupId")
	@JsonIgnore
	public AccessGroup getParentGroup() {
		return parentGroup;
	}

	public void setParentGroup(AccessGroup parentGroup) {
		this.parentGroup = parentGroup;
	}

	@OneToMany(mappedBy = "parentGroup")
	public List<AccessGroup> getChildGroups() {
		return childGroups;
	}

	public void setChildGroups(List<AccessGroup> childGroups) {
		this.childGroups = childGroups;
	}

	@ManyToOne
	@JoinColumn(name = "teamId")
	@JsonIgnore
	public Organization getTeam() {
		return team;
	}

	public void setTeam(Organization team) {
		this.team = team;
	}
	
}
