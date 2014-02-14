package com.denimgroup.threadfix.importer.exception;

public class MappingException extends RuntimeException {

    private final String code;

    public String getCode() {
        return code;
    }

    public MappingException(String code) {
        super("Unable to complete lookup using the code " + code);

        this.code = code;
    }

}
