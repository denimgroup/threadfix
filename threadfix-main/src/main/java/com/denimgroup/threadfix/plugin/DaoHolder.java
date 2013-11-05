package com.denimgroup.threadfix.plugin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;

public class DaoHolder extends SpringBeanAutowiringSupport {
    @Autowired
    public ChannelVulnerabilityDao channelVulnerabilityDao;
    @Autowired
    public ChannelSeverityDao channelSeverityDao;
    @Autowired
    public ChannelTypeDao channelTypeDao;
    @Autowired
    public GenericVulnerabilityDao genericVulnerabilityDao;
}