package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;

/**
 * Created by mhatzenbuehler on 7/3/2014.
 */
public class PMDChannelImporter extends AbstractChannelImporter {
    public PMDChannelImporter() {
        super(ScannerType.PMD);
    }

    @Override
    @Transactional
    public Scan parseInput() {
        Scan returnScan = parseSAXInput(new PmdSAXParser());
        return returnScan;
    }

    public class PmdSAXParser extends HandlerWithBuilder {
        public void add(Finding finding) {
            if (finding != null) {
                //do possible other stuff here
                //finding.setNativeId(getNativeId(finding));
                //finding.setIsStatic(true);
                saxFindingList.add(finding);
            }
        }
    }

    @Nonnull
    @Override
    public ScanCheckResultBean checkFile() {
        return new ScanCheckResultBean(ScanImportStatus.EMPTY_SCAN_ERROR)   ;
    }
}
