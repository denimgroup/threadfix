////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;

import com.denimgroup.threadfix.framework.engine.CodePoint;

@Entity
@Table(name = "DataFlowElement")
public class DataFlowElement extends BaseEntity implements Comparable<DataFlowElement>, CodePoint {

	private static final long serialVersionUID = 1709906845656363680L;

	public static final int SOURCE_FILE_NAME_LENGTH = 250;
	public static final int LINE_TEXT_LENGTH = 250;
	
	@Size(max = SOURCE_FILE_NAME_LENGTH, message = "{errors.maxlength} " + SOURCE_FILE_NAME_LENGTH + ".")
	private String sourceFileName;
	private int lineNumber;
	private int columnNumber;

	@Size(max = LINE_TEXT_LENGTH, message = "{errors.maxlength} " + LINE_TEXT_LENGTH + ".")
	private String lineText;
	private Finding finding;
	private int sequence;
	
	public DataFlowElement(){}
	
	public DataFlowElement(String sourceFileName, int lineNumber, String lineText) {
		this.sourceFileName = sourceFileName;
		this.lineNumber = lineNumber;
		this.lineText = lineText;
	}

	public DataFlowElement(String sourceFileName, int lineNumber, String lineText, int sequence) {
		this.sourceFileName = sourceFileName;
		this.lineNumber = lineNumber;
		this.lineText = lineText;
		this.sequence = sequence;
	}

	@Column(length = SOURCE_FILE_NAME_LENGTH)
	public String getSourceFileName() {
		return sourceFileName;
	}

	public void setSourceFileName(String sourceFileName) {
		this.sourceFileName = sourceFileName;
	}

	@Basic
	public int getLineNumber() {
		return lineNumber;
	}

	public void setLineNumber(int lineNumber) {
		this.lineNumber = lineNumber;
	}

	@Basic
	public int getColumnNumber() {
		return columnNumber;
	}

	public void setColumnNumber(int columnNumber) {
		this.columnNumber = columnNumber;
	}

	@Column(length = LINE_TEXT_LENGTH)
	public String getLineText() {
		return lineText;
	}

	public void setLineText(String lineText) {
		this.lineText = lineText;
	}

	@ManyToOne
	@JoinColumn(name = "findingId")
	@JsonIgnore
	public Finding getFinding() {
		return finding;
	}

	public void setFinding(Finding finding) {
		this.finding = finding;
	}

	@Basic
	public int getSequence() {
		return sequence;
	}

	public void setSequence(int sequence) {
		this.sequence = sequence;
	}

	@Override
	public int compareTo(DataFlowElement o) {
		if (o == null)
			return 0;
		else if (this.sequence == o.sequence)
			return 0;
		else if (this.sequence > o.sequence)
			return 1;
		else
			return -1;
	}
}
