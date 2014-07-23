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

package com.denimgroup.threadfix.service.report;

import java.text.DateFormatSymbols;
import java.util.Calendar;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class YearAndMonth implements Comparable<YearAndMonth> {
	
	private static final String[] months = new DateFormatSymbols().getMonths();
	
	private int year, month;
	YearAndMonth(int year, int month) { this.year = year; this.month = month; }
	YearAndMonth(Calendar calendar) { 
		this.year = calendar.get(Calendar.YEAR);
		this.month = calendar.get(Calendar.MONTH) + 1;
	}
	public YearAndMonth next() {
		return addMonths(1);
	}
	
	public String toString() {
		return "" + year + "-" + month;
	}
	
	public YearAndMonth addMonths(int num) {
		if (num == 0) { return this; }
		
		if (month + num > 12) {
			return new YearAndMonth(year + ((month + num) / 12), ((month + num) % 12));
		} else if (month + num < 1) {
			return new YearAndMonth(year - 1 - ((month + num) / 12), ((month + num) % 12) + 12);
		} else {
			return new YearAndMonth(year, month + num);
		}
	}
	
	public List<YearAndMonth> pastXMonths(int numMonths) {
		YearAndMonth array[] = new YearAndMonth[numMonths];
		
		for (int i = 0; i < numMonths; i ++) {
			array[i] = this.addMonths(- i);
		}
		
		return list(array);
	}
	
	public String getMonthName() {
		return months[month-1];
	}
	
	@Override
	public int compareTo(YearAndMonth o) {
		
		int retVal;
		
		if (o.year > this.year) {
			retVal = -1;
		} else if (this.year > o.year) {
			retVal = 1;
		} else if (o.month > this.month)  {
			retVal = -1;
		} else if (this.month > o.month) {
			retVal = 1;
		} else {
			retVal = 0;
		}
		
		return(retVal);
	}
	
	public boolean equals(Object o) {
		if (o != null && o instanceof YearAndMonth) {
			YearAndMonth object = (YearAndMonth) o;
			return object.year == this.year && object.month == this.month;
		} else {
			return false;
		}
	}
	
	public int hashCode() {
		return year * 100 + month;
	}
}