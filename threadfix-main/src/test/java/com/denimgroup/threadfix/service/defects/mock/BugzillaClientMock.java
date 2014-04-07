package com.denimgroup.threadfix.service.defects.mock;

import com.denimgroup.threadfix.service.defects.utils.bugzilla.BugzillaClient;
import org.apache.xmlrpc.XmlRpcException;

import java.util.Map;

/**
 * Created by denimgroup on 4/7/14.
 */
public class BugzillaClientMock implements BugzillaClient{

    //TODO mock against BugzillaClientImpl.java, check return values for all methods

    @Override
    public ConnectionStatus configure(String url, String username, String password) {
        return null;
    }

    @Override
    public Map<String, Integer> createBug(Map<String, String> bugMap) throws XmlRpcException {
        return null;
    }

    @Override
    public boolean checkUrl(String url) {
        return false;
    }

    @Override
    public Object executeMethod(String method) throws XmlRpcException {
        return null;
    }

    @Override
    public Object executeMethod(String method, Object... params) throws XmlRpcException {
        return null;
    }
}
