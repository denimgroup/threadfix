package com.denimgroup.threadfix.service;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;

@Service
public class RequestUrlServiceImpl implements RequestUrlService {

    @Override
    public String getBaseUrlFromRequest(HttpServletRequest request) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int port = request.getServerPort();
        String contextPath = request.getContextPath();

        if (port == 443 || port == 80){
            return String.format("%s://%s%s", scheme, serverName, contextPath);
        } else {
            return String.format("%s://%s:%d%s", scheme, serverName, port, contextPath);
        }
    }
}
