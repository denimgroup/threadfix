////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
import javax.persistence.Table;

@Entity
@Table(name = "DeletedDataFlowElement")
public class DeletedDataFlowElement extends AuditableEntity{

	public DeletedDataFlowElement(DataFlowElement originalElement) {
		if (originalElement != null) {
			setSourceFileName(originalElement.getSourceFileName());
			setColumnNumber(originalElement.getColumnNumber());
			setLineNumber(originalElement.getLineNumber());
			setLineText(originalElement.getLineText());
			setSequence(originalElement.getSequence());
			setId(originalElement.getId());
			
			if (originalElement.getFinding() != null) {
				setDeletedFindingId(originalElement.getFinding().getId());
			}
		}
	}
	
	private static final long serialVersionUID = 17679467954663680L;

	private String sourceFileName, lineText;
	private int lineNumber, sequence, columnNumber;

	private Integer findingId;
	
	@Column(length = DataFlowElement.SOURCE_FILE_NAME_LENGTH)
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
	
	@Column(length = DataFlowElement.LINE_TEXT_LENGTH)
	public String getLineText() {
		return lineText;
	}
	
	public void setLineText(String lineText) {
		this.lineText = lineText;
	}
	
	@Column
	public Integer getDeletedFindingId() {
		return findingId;
	}
	
	public void setDeletedFindingId(Integer findingId) {
		this.findingId = findingId;
	}
	
	@Basic
	public int getSequence() {
		return sequence;
	}
	
	public void setSequence(int sequence) {
		this.sequence = sequence;
	}
}
