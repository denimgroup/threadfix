package com.denimgroup.threadfix.plugins.intellij.rest;

import org.jetbrains.annotations.NotNull;

/**
 * Created by mac on 12/13/13.
 */
public class RestResponse {

    public final String text;
    public final int status;

    private final String textStart;

    public RestResponse(@NotNull String text, int status) {
        this.text = text;
        this.status = status;

        String test = text.trim();

        int size = test.length();

        if (size < 20) {
            textStart = test;
        } else {
            textStart = test.substring(0, 19);
        }
    }

    @Override
    public String toString() {
        return "Status: " + status + ", text: " + textStart;
    }
}
