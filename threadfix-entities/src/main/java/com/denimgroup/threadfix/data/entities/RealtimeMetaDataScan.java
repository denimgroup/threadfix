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

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.annotations.Cascade;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;


@Entity
@Table(name="SCAN")
@DiscriminatorValue("R")
public class RealtimeMetaDataScan extends Scan {

    private Integer numberRealtimeCriticalVulnerabilities = 0;
    private Integer numberRealtimeHighVulnerabilities = 0;
    private Integer numberRealtimeCriticalAuditedVulnerabilities = 0;
    private Integer numberRealtimeHighAuditedVulnerabilities = 0;
    private Integer numberTotalAuditedVulnerabilities = 0;
    private RemoteProviderApplication remoteProviderApplication;

    @Column
    public Integer getNumberTotalAuditedVulnerabilities() {
        return numberTotalAuditedVulnerabilities;
    }

    public void setNumberTotalAuditedVulnerabilities(Integer numberTotalAuditedVulnerabilities) {
        this.numberTotalAuditedVulnerabilities = numberTotalAuditedVulnerabilities;
    }

    @Column
    public Integer getNumberRealtimeCriticalVulnerabilities() {
        return numberRealtimeCriticalVulnerabilities;
    }

    public void setNumberRealtimeCriticalVulnerabilities(Integer numberRealtimeCriticalVulnerabilities) {
        this.numberRealtimeCriticalVulnerabilities = numberRealtimeCriticalVulnerabilities;
    }

    @Column
    public Integer getNumberRealtimeHighVulnerabilities() {
        return numberRealtimeHighVulnerabilities;
    }

    public void setNumberRealtimeHighVulnerabilities(Integer numberRealtimeHighVulnerabilities) {
        this.numberRealtimeHighVulnerabilities = numberRealtimeHighVulnerabilities;
    }

    @Column
    public Integer getNumberRealtimeCriticalAuditedVulnerabilities() {
        return numberRealtimeCriticalAuditedVulnerabilities;
    }

    public void setNumberRealtimeCriticalAuditedVulnerabilities(Integer numberRealtimeCriticalAuditedVulnerabilities) {
        this.numberRealtimeCriticalAuditedVulnerabilities = numberRealtimeCriticalAuditedVulnerabilities;
    }

    @Column
    public Integer getNumberRealtimeHighAuditedVulnerabilities() {
        return numberRealtimeHighAuditedVulnerabilities;
    }

    public void setNumberRealtimeHighAuditedVulnerabilities(Integer numberRealtimeHighAuditedVulnerabilities) {
        this.numberRealtimeHighAuditedVulnerabilities = numberRealtimeHighAuditedVulnerabilities;
    }

    @OneToOne(cascade = {CascadeType.MERGE,CascadeType.REMOVE})
    @JoinColumn(name = "remoteProviderApplicationId")
    @Cascade(value = org.hibernate.annotations.CascadeType.DELETE)
    @JsonIgnore
    public RemoteProviderApplication getRemoteProviderApplication() {
        return remoteProviderApplication;
    }

    public void setRemoteProviderApplication(RemoteProviderApplication remoteProviderApplication) {
        this.remoteProviderApplication = remoteProviderApplication;
    }

}
