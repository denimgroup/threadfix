package com.denimgroup.threadfix.importer.testutils;

import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;

import java.util.List;

/**
 * Created by mac on 2/4/14.
 */
public class ChannelImporterMocker {

    /**
     *   @Autowired
         protected ChannelVulnerabilityDao channelVulnerabilityDao;
         @Autowired
         protected ChannelSeverityDao channelSeverityDao;
         @Autowired
         protected ChannelTypeDao channelTypeDao;
         @Autowired
         protected GenericVulnerabilityDao genericVulnerabilityDao;
     * @param importer
     */
    public static void mockIt(ChannelImporter importer) {
        ChannelVulnerabilityDao channelVulnerabilityDao = new ChannelVulnerabilityDao() {
            @Override
            public ChannelVulnerability retrieveByCode(ChannelType channelType, String code) {
                ChannelVulnerability vuln = new ChannelVulnerability();

                vuln.setCode(code);
                vuln.setChannelType(channelType);

                return vuln;
            }

            @Override
            public ChannelVulnerability retrieveByName(ChannelType channelType, String name) {
                ChannelVulnerability vuln = new ChannelVulnerability();

                vuln.setName(name);
                vuln.setChannelType(channelType);

                return vuln;
            }

            @Override
            public boolean hasMappings(int id) {
                return false;
            }

            @Override
            public ChannelVulnerability retrieveById(int id) {
                return null;
            }

            @Override
            public List<ChannelVulnerability> retrieveSuggested(String prefix) {
                return null;
            }

            @Override
            public void saveOrUpdate(ChannelVulnerability channelVulnerability) {

            }

            @Override
            public boolean isValidManualName(String name) {
                return false;
            }

            @Override
            public List<ChannelVulnerability> retrieveAllManual() {
                return null;
            }
        };

    }


}
