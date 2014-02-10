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

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name="ScheduledScan")
public class ScheduledScan extends AuditableEntity {

	private static final long serialVersionUID = 23434234234L;

	public enum ScheduledFrequencyType {
		DAILY("Daily"),
		WEEKLY("Weekly");
//		STATUS_COMPLETE_SUCCESSFUL("Monthly")
//        ;
		
		private String description;
		
		public String getDescription() {
			return this.description;
		}
		
		private ScheduledFrequencyType(String description) {
			this.description = description;
		}

        public static ScheduledFrequencyType getFrequency(String keyword) {
            for (ScheduledFrequencyType t: values()) {
                if (keyword.equalsIgnoreCase(t.getDescription())) {
                    return t;
                }
            }
            return null;
        }
	}

    public enum ScheduledPeriodType {
        AM("AM"),
        PM("PM");

        private String period;

        public String getPeriod() {
            return this.period;
        }

        private ScheduledPeriodType(String period) {
            this.period = period;
        }

        public static ScheduledPeriodType getPeriod(String keyword) {
            for (ScheduledPeriodType t: values()) {
                if (keyword.equalsIgnoreCase(t.getPeriod())) {
                    return t;
                }
            }
            return null;
        }
    }

    public enum DayInWeek {
        MON("Mon"),
        TUE("Tue"),
        WED("Wed"),
        THU("Thu"),
        FRI("Fri"),
        SAT("Sat"),
        SUN("Sun");

        private String day;

        public String getDay() {
            return this.day;
        }

        private DayInWeek(String day) {
            this.day = day;
        }

        public static DayInWeek getDay(String keyword) {
            for (DayInWeek t: values()) {
                if (keyword != null && keyword.equalsIgnoreCase(t.getDay())) {
                    return t;
                }
            }
            return null;
        }
    }

	private Application application;
    private int hour, minute;
    private String period, day;
    private String scanner, frequency;
    private String dateError;

	@ManyToOne
	@JoinColumn(name = "applicationId")
	@JsonIgnore
	public Application getApplication() {
		return this.application;	}
	
	public void setApplication(Application application) {
		this.application = application;
	}

    @Column(nullable=false)
    public int getHour() {
        return hour;
    }

    public void setHour(int hour) {
        this.hour = hour;
    }

    @Column(nullable=false)
    public int getMinute() {
        return minute;
    }

    public void setMinute(int minute) {
        this.minute = minute;
    }

    @Column(nullable=false)
    public String getPeriod() {
        return period;
    }

    public void setPeriod(String period) {
        this.period = period;
    }

    @Column(nullable=true)
    public String getDay() {
        return day;
    }

    public void setDay(String day) {
        this.day = day;
    }

    @Column(nullable=false)
    public String getFrequency() {
        return frequency;
    }

    public void setFrequency(String frequency) {
        this.frequency = frequency;
    }

    @Column(nullable=false)
    public String getScanner() {
        return scanner;
    }

    public void setScanner(String scanner) {
        this.scanner = scanner;
    }

    @Transient
    public String getDateError() {
        return dateError;
    }

    public void setDateError(String dateError) {
        this.dateError = dateError;
    }
}
