package com.denimgroup.threadfix.service;

public interface ContentTypeService {
	boolean isWhiteList(String contentType);
	boolean isBlackList(String contentType);
	boolean isStrictWhiteList();
	String translateContentType(String contentType);
	boolean isValidUpload(String contentType);
	String getDefaultType();
}
