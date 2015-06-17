package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.ScanResultFilter;

import java.util.List;

public interface ScanResultFilterService {
    List<ScanResultFilter> loadAll();

    void storeAndApplyFilter(ScanResultFilter scanResultFilter);

    ScanResultFilter loadById(int scanResultFilterId);

    void delete(ScanResultFilter scanResultFilter);

    List<GenericSeverity> loadFilteredSeveritiesForChannelType(ChannelType channelType);

    ScanResultFilter loadByChannelTypeAndSeverity(ChannelType channelType, GenericSeverity genericSeverity);

    void storeAndApplyFilter(ScanResultFilter scanResultFilter, GenericSeverity previousGenericSeverity, ChannelType previousChannelType);
}
