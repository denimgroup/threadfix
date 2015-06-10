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
import org.hibernate.annotations.Index;

import javax.persistence.*;

/**
 * Created by mcollins on 5/13/15.
 */
@Entity
@Table(name = "StatisticsCounter")
public class StatisticsCounter extends BaseEntity {

    Integer scanId,
            vulnerabilityId,
            originalGenericSeverityId,
            currentGenericSeverityId,
            genericVulnerabilityId,
            channelSeverityId,
            channelVulnerabilityId;

    Finding finding;

    ScanRepeatFindingMap scanRepeatFindingMap;

    @ManyToOne
    @JsonIgnore
    @JoinColumn(name = "findingId")
    @Index(name="findingId")
    public Finding getFinding() {
        return finding;
    }

    public void setFinding(Finding finding) {
        this.finding = finding;
    }

    @ManyToOne
    @JsonIgnore
    @JoinColumn(name = "scanRepeatFindingMapId")
    @Index(name="scanRepeatFindingMapId")
    public ScanRepeatFindingMap getScanRepeatFindingMap() {
        return scanRepeatFindingMap;
    }

    public void setScanRepeatFindingMap(ScanRepeatFindingMap scanRepeatFindingMap) {
        this.scanRepeatFindingMap = scanRepeatFindingMap;
    }

    @Column
    @Index(name="scanId")
    public Integer getScanId() {
        return scanId;
    }

    public void setScanId(Integer scanId) {
        this.scanId = scanId;
    }

    @Column
    @Index(name="vulnerabilityId")
    public Integer getVulnerabilityId() {
        return vulnerabilityId;
    }

    public void setVulnerabilityId(Integer vulnerabilityId) {
        this.vulnerabilityId = vulnerabilityId;
    }

    @Column
    @Index(name="originalGenericSeverityId")
    public Integer getOriginalGenericSeverityId() {
        return originalGenericSeverityId;
    }

    public void setOriginalGenericSeverityId(Integer originalGenericSeverityId) {
        this.originalGenericSeverityId = originalGenericSeverityId;
    }

    @Column
    @Index(name="currentGenericSeverityId")
    public Integer getCurrentGenericSeverityId() {
        return currentGenericSeverityId;
    }

    public void setCurrentGenericSeverityId(Integer currentGenericSeverityId) {
        this.currentGenericSeverityId = currentGenericSeverityId;
    }

    @Column
    @Index(name="currentChannelSeverityId")
    public Integer getChannelSeverityId() {
        return channelSeverityId;
    }

    public void setChannelSeverityId(Integer channelSeverityId) {
        this.channelSeverityId = channelSeverityId;
    }

    @Column
    @Index(name="currentChannelVulnerabilityId")
    public Integer getChannelVulnerabilityId() {
        return channelVulnerabilityId;
    }

    public void setChannelVulnerabilityId(Integer channelVulnerabilityId) {
        this.channelVulnerabilityId = channelVulnerabilityId;
    }

    @Column
    @Index(name="genericVulnerabilityId")
    public Integer getGenericVulnerabilityId() {
        return genericVulnerabilityId;
    }

    public void setGenericVulnerabilityId(Integer genericVulnerabilityId) {
        this.genericVulnerabilityId = genericVulnerabilityId;
    }

    public static StatisticsCounter getStatisticsCounter(Finding finding) {
        if (finding != null &&
                finding.getVulnerability() != null &&
                finding.isFirstFindingForVuln() &&
                finding.getChannelSeverity() != null &&
                finding.getChannelVulnerability() != null &&
                finding.getScan() != null &&
                finding.getVulnerability().getGenericSeverity() != null &&
                finding.getVulnerability().getGenericVulnerability() != null) {

            StatisticsCounter counter = new StatisticsCounter();

            counter.vulnerabilityId           = finding.getVulnerability().getId();
            counter.scanId                    = finding.getScan().getId();
            counter.channelSeverityId         = finding.getChannelSeverity().getId();
            counter.channelVulnerabilityId    = finding.getChannelVulnerability().getId();
            counter.currentGenericSeverityId  = finding.getVulnerability().getGenericSeverity().getId();
            counter.genericVulnerabilityId    = finding.getVulnerability().getGenericVulnerability().getId();
            counter.originalGenericSeverityId = counter.currentGenericSeverityId;
            counter.finding = finding;

            return counter;
        } else {
            return null;
        }
    }

    public static StatisticsCounter getStatisticsCounter(ScanRepeatFindingMap map) {

        if (map != null && map.getFinding() != null && map.getScan() != null) {
            StatisticsCounter statisticsCounter = getStatisticsCounter(map.getFinding());
            if (statisticsCounter == null) {
                return null;
            }
            statisticsCounter.scanId = map.getScan().getId();
            statisticsCounter.setScanRepeatFindingMap(map);
            return statisticsCounter;
        } else {
            return null;
        }
    }
}
