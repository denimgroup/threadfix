////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.views.AllViews;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonView;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.Calendar;

@Entity
@Table(name = "RemoteProviderApplication")
public class RemoteProviderApplication extends AuditableEntity  {
	
	private static final long serialVersionUID = 5023873433359926246L;

	// Veracode Build numbers / whatever WhiteHat has.
	// TODO checking on this
	public static final int NATIVE_ID_LENGTH = 1024;
	public static final int NATIVE_NAME_LENGTH = 1024;

	@Size(max = NATIVE_ID_LENGTH, message = "{errors.maxlength} " + NATIVE_ID_LENGTH + ".")
	private String nativeId;

    @Size(max = NATIVE_NAME_LENGTH, message = "{errors.maxlength} " + NATIVE_NAME_LENGTH + ".")
	private String nativeName;

    @Size(max = NATIVE_NAME_LENGTH, message = "{errors.maxlength} " + NATIVE_NAME_LENGTH + ".")
	private String customName;
	
	private RemoteProviderType remoteProviderType;
	
	private Application application;
	private ApplicationChannel applicationChannel;
	
	private Calendar lastImportTime;

	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getLastImportTime() {
		return lastImportTime;
	}

	public void setLastImportTime(Calendar lastImportTime) {
		this.lastImportTime = lastImportTime;
	}

	@Column(length = NATIVE_ID_LENGTH, name = "name")
    @JsonView(AllViews.TableRow.class)
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}

    //
    // nativeId used to store the application name instead of the native application id.
    // To preserve the db schema, we've reassigned the column name for nativeId to the nativeName property.
	//
    @Column(length = NATIVE_NAME_LENGTH, name = "nativeId")
    @JsonView(AllViews.TableRow.class)
	public String getNativeName() {
		return nativeName;
	}

	public void setNativeName(String nativeName) {
		this.nativeName = nativeName;
	}

	@ManyToOne
	@JoinColumn(name = "remoteProviderTypeId")
	@JsonIgnore
	public RemoteProviderType getRemoteProviderType() {
		return remoteProviderType;
	}

	public void setRemoteProviderType(RemoteProviderType remoteProviderType) {
		this.remoteProviderType = remoteProviderType;
	}

	@ManyToOne
	@JoinColumn(name = "applicationId")
    @JsonView(AllViews.TableRow.class)
	public Application getApplication() {
		return application;
	}

	public void setApplication(Application application) {
		this.application = application;
	}

	@OneToOne
	public ApplicationChannel getApplicationChannel() {
		return applicationChannel;
	}
	
	public void setApplicationChannel(ApplicationChannel applicationChannel) {
		this.applicationChannel = applicationChannel;
	}

    @Column
    @JsonView(AllViews.TableRow.class)
    public String getCustomName() {
        return customName;
    }

    public void setCustomName(String customName) {
        this.customName = customName;
    }
}
