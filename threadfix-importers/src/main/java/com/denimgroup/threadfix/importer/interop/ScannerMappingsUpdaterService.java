package com.denimgroup.threadfix.importer.interop;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Calendar;
import java.util.List;

public interface ScannerMappingsUpdaterService {

    static class ScanPluginCheckBean {
        public final boolean canUpdate;
        public final Calendar lastImportDate;
        public final Calendar currentPluginDate;

        public boolean isCanUpdate() {
            return canUpdate;
        }

        public Calendar getLastImportDate() {
            return lastImportDate;
        }

        public Calendar getCurrentPluginDate() {
            return currentPluginDate;
        }

        public ScanPluginCheckBean(boolean canUpdate, Calendar lastImportDate, Calendar currentPluginDate) {
            this.canUpdate = canUpdate;
            this.lastImportDate = lastImportDate;
            this.currentPluginDate = currentPluginDate;
        }
    }

    /**
     *
     * @return
     */
    ScanPluginCheckBean checkPluginJar();

    /**
     *
     *
     */
    List<String[]> updateChannelVulnerabilities() throws IOException, URISyntaxException;

    /**
     *
     */
    List<String> getSupportedScanners();

}
