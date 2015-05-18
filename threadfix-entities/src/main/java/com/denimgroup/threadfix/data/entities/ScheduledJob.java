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

import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;

@MappedSuperclass
public abstract class ScheduledJob extends AuditableEntity {

    private static final long serialVersionUID = -6708004595025396502L;

    protected int hour, minute;
    protected String period, day;
    protected String frequency;
    protected String dateError;

    @Column(nullable=false)
    @JsonView(Object.class)
    public int getHour() {
        return hour;
    }

    public void setHour(int hour) {
        this.hour = hour;
    }

    @Column(nullable=false)
    @JsonView(Object.class)
    public int getMinute() {
        return minute;
    }

    public void setMinute(int minute) {
        this.minute = minute;
    }

    @Column(nullable=false)
    @JsonView(Object.class)
    public String getPeriod() {
        return period;
    }

    public void setPeriod(String period) {
        this.period = period;
    }

    @Column(nullable=true)
    @JsonView(Object.class)
    public String getDay() {
        return day;
    }

    public void setDay(String day) {
        this.day = day;
    }

    @Column(nullable=false)
    @JsonView(Object.class)
    public String getFrequency() {
        return frequency;
    }

    public void setFrequency(String frequency) {
        this.frequency = frequency;
    }

    @Transient
    public String getDateError() {
        return dateError;
    }

    public void setDateError(String dateError) {
        this.dateError = dateError;
    }

    @Transient
    @JsonView(Object.class)
    public String getScheduledDate(){
        String scheduledDate;

        if (this.day==null){
            scheduledDate = this.frequency + " at " + this.hour
                    + ":" + (this.minute == 0 ? "00" : this.minute);
        } else {
            scheduledDate = this.day + "s at " + this.hour
                    + ":" + (this.minute == 0 ? "00" : this.minute);
        }

        return scheduledDate;
    }
}
