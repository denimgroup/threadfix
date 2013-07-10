package com.denimgroup.threadfix.service.report;

import java.text.DateFormatSymbols;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

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
		
		return Arrays.asList(array);
	}
	
	public String getMonthName() {
		return months[month-1];
	}
	
	@Override
	public int compareTo(YearAndMonth o) {
		
		int retVal;
		
		YearAndMonth other = ((YearAndMonth) o);
		if (other.year > this.year) {
			retVal = -1;
		} else if (this.year > other.year) {
			retVal = 1;
		} else if (other.month > this.month)  {
			retVal = -1;
		} else if (this.month > other.month) {
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