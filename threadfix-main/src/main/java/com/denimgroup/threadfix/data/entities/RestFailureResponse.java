package com.denimgroup.threadfix.data.entities;

public class RestFailureResponse {
	private String status = "failed";
	private String message;
	
	public RestFailureResponse(String message) {
		this.message = message;
	}
	
	public String getMessage() {
		return(this.message);
	}
	
	public String getStatus() {
		return(this.status);
	}
}
