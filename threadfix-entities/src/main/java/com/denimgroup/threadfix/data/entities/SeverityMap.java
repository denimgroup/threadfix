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

@Entity
@Table(name = "SeverityMap")
public class SeverityMap extends BaseEntity {

	private static final long serialVersionUID = 4573108302895736186L;

	private ChannelSeverity channelSeverity;
	private GenericSeverity genericSeverity;

	@OneToOne(cascade = CascadeType.ALL)
	@JoinColumn(name = "channelSeverityId")
	@JsonIgnore
	public ChannelSeverity getChannelSeverity() {
		return channelSeverity;
	}

	public void setChannelSeverity(ChannelSeverity channelSeverity) {
		this.channelSeverity = channelSeverity;
	}

	@OneToOne(cascade = CascadeType.ALL)
	@JoinColumn(name = "genericSeverityId")
	@JsonView(Object.class)
	public GenericSeverity getGenericSeverity() {
		return genericSeverity;
	}

	public void setGenericSeverity(GenericSeverity genericSeverity) {
		this.genericSeverity = genericSeverity;
	}

}
