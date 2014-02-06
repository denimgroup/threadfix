package com.denimgroup.threadfix.webapp.controller.rest;

/**
 * Created by mac on 1/27/14.
 */
public class ScanQueueTaskConfigException extends Exception {

    private String message;

    public ScanQueueTaskConfigException(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
