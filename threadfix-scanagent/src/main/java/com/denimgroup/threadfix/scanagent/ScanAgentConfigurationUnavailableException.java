package com.denimgroup.threadfix.scanagent;

/**
 * Created by mac on 1/27/14.
 */
public class ScanAgentConfigurationUnavailableException extends RuntimeException {

    public ScanAgentConfigurationUnavailableException(String message, Throwable previous) {
        super(message, previous);
    }

}
