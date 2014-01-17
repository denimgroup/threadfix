package com.denimgroup.threadfix.plugin.eclipse.util;

import com.google.gson.Gson;

public class RestResponse {

	public static RestResponse getResponse(String text, int status) {

        RestResponse response = null;

        if (!text.trim().isEmpty() && text.trim().indexOf('{') == 0) {
			response = new Gson().fromJson(text, RestResponse.class);
            
            if (response != null) {
	            System.out.println(response.success);
	            System.out.println(response.message);
	            System.out.println(response.object);
            }
        }
        
        if (response == null){
            System.out.println("Invalid JSON object received: \n" + text);
            System.out.println("Was this a pre-2.0M2 threadfix build?");
        }

        if (response == null) {
            response = new RestResponse(null, status, false, "The response deserialization failed.");
        } else {
            response.status = status;
        }

        return response;
    }

    public Object object;
    public String message;
    public int status;
    public boolean success;
    
    private RestResponse(Object object, int status, boolean success, String message) {
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
