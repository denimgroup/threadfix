package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.ScanResultFilter;

import java.util.List;

public interface ScanResultFilterDao extends GenericObjectDao<ScanResultFilter>{
    void delete(ScanResultFilter scanResultFilter);

    List<GenericSeverity> loadFilteredSeveritiesForChannelType(ChannelType channelType);

    ScanResultFilter loadByChannelTypeAndSeverity(ChannelType channelType, GenericSeverity genericSeverity);

    List<Integer> retrieveAllChannelSeverities();

    List<Integer> retrieveAllChannelSeveritiesByChannelType(ChannelType channelType);
}
