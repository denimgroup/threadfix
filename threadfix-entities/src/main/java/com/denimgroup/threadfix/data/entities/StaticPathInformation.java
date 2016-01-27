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


import com.denimgroup.threadfix.data.enums.FrameworkType;

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
	
	@Transient
	public FrameworkType guessFrameworkType() {
		if (name != null && name.equals(SPRING_MVC_TYPE)) {
			return FrameworkType.SPRING_MVC;
		} else {
			return FrameworkType.NONE;
		}
	}
}
