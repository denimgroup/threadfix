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
