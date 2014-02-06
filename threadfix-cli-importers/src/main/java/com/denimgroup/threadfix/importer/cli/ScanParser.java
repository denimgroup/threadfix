package com.denimgroup.threadfix.importer.cli;

import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.interop.ScanCheckResultBean;
import com.denimgroup.threadfix.importer.interop.ScanImportStatus;
import com.denimgroup.threadfix.importer.parser.ThreadFixBridge;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;

@Component
public class ScanParser {

    @Autowired
    ThreadFixBridge bridge;
    @Autowired
    ChannelTypeDao channelTypeDao;

    /**
     *
     * @param filePath path to a file. Will throw exceptions if not valid
     * @return the String output
     */
    @Transactional(readOnly = false)
    public String readFile(String filePath) {
        if (bridge == null) {
            throw new IllegalStateException("Spring configuration is broken, please fix autowiring.");
        }

        final String result;

        File scanFile = new File(filePath);

        ScannerType scannerType = bridge.getType(scanFile);

        if (scannerType == null) {
            result = "Unable to determine the scan type of the file.";
        } else {
            ScanCheckResultBean resultBean = bridge.testScan(scannerType, scanFile);

            if (resultBean.getScanCheckResult() == ScanImportStatus.SUCCESSFUL_SCAN) {
                result = new ScanSerializer().toCSVString(bridge.getScan(scannerType, scanFile));
            } else {
                result = "Scan check failed and returned the following status: " + resultBean.getScanCheckResult();
            }
        }

        return result;
    }


}
