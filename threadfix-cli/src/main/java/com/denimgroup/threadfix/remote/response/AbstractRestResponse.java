package com.denimgroup.threadfix.remote.response;

/**
 * Created by mac on 1/20/14.
 */
public abstract class AbstractRestResponse {
    public boolean success = false;
    public String message = null;
    public int responseCode = 200;
}
