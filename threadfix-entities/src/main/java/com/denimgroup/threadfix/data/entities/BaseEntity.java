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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import java.io.Serializable;

/**
 * A base class for all entities that ensures Serialization and PK generation.
 * 
 * A primer on annotations is below. More information can be obtained from the
 * Hibernate docs here:
 * 
 * http://docs.jboss.org/hibernate/stable/annotations/reference/en/html_single/
 * 
 * @Column( name="columnName"; (1) boolean unique() default false; (2) boolean
 *          nullable() default true; (3) boolean insertable() default true; (4)
 *          boolean updatable() default true; (5) String columnDefinition()
 *          default ""; (6) String table() default ""; (7) int length() default
 *          255; (8) int precision() default 0; // decimal precision (9) int
 *          scale() default 0; // decimal scale
 * 
 * @author bbeverly
 * 
 */
@MappedSuperclass
public class BaseEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	private Integer id = null;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
    @JsonView(Object.class)
	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	@Transient
	@JsonIgnore
	public boolean isNew() {
		return this.getId() == null;
	}
}
