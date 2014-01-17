package com.denimgroup.threadfix.plugin.eclipse.rest;

import com.denimgroup.threadfix.plugin.eclipse.util.VulnerabilityMarker;
import com.google.gson.Gson;

public class MarkersResponse {

    public static MarkersResponse getResponse(String text, int status) {

    	MarkersResponse response = null;

        if (!text.trim().isEmpty() && text.trim().indexOf('{') == 0) {
            response = new Gson().fromJson(text, MarkersResponse.class);
        } else {
            System.out.println("Invalid JSON object received: \n" + text);
            System.out.println("Was this a pre-2.0M2 threadfix build?");
        }

        if (response == null) {
            response = new MarkersResponse(null, status, false, "The response deserialization failed.");
        } else {
            response.status = status;
        }

        return response;
    }

    public VulnerabilityMarker[] object;
    public String message;
    public int status;
    public boolean success;
    
    private MarkersResponse() {}

    private MarkersResponse(VulnerabilityMarker[] object, int status, boolean success, String message) {
        this.object = object;
        this.status = status;
        this.success = success;
        this.message = message;
    }

    @Override
    public String toString() {
        return "RestResponse{" +
                "object=" + object +
                ", message='" + message + '\'' +
                ", status=" + status +
                ", success=" + success +
                '}';
    }
}
