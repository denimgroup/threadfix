////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.importer.cli;

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.importer.parser.ThreadFixBridge;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import java.io.File;

@Component
public class ScanParser {

    @Autowired
    ThreadFixBridge               bridge;
    @Autowired
    ChannelTypeDao                channelTypeDao;
    @Autowired
    ScannerMappingsUpdaterService mappingsUpdaterService;

    private boolean needsUpdating = true;

    private void checkForUpdate() {
        if (needsUpdating) {
            try {
                mappingsUpdaterService.updateMappings(SpringConfiguration.getContext());
                needsUpdating = false;
            } catch (Exception e) { // this isn't production code, and I'm rethrowing as RuntimeException
                throw new IllegalStateException("Encountered error while updating channel vulns. Fix it.", e);
            }
        }
    }

    /**
     *
     * @param filePath path to a file. Will throw exceptions if not valid
     * @return the String output
     */
    @Transactional(readOnly = false) // used to be true
    public String readFile(@Nonnull String filePath) {
        if (bridge == null) {
            throw new IllegalStateException("Spring configuration is broken, please fix autowiring.");
        }
        try {
            return ScanSerializer.toCSVString(getScan(filePath));
        } catch (TypeParsingException e) {
            return "Unable to determine the scan type of the file.";
        } catch (ScanTestingException e) {
            return "Scan check failed and returned the following status: " + e.status;
        } catch (ScanFileNotFoundException e) {
            return "Scan file was not found.";
        }
    }

    @Transactional(readOnly = false) // used to be true
    public ScanCheckResultBean testScan(@Nonnull String filePath) throws TypeParsingException, ScanTestingException {
        return testScan(new File(filePath));
    }

    @Transactional(readOnly = false) // used to be true
    public ScanCheckResultBean testScan(@Nonnull File file) throws TypeParsingException, ScanTestingException {
        if (!file.exists()) {
            throw new ScanFileNotFoundException("Scan file not found: " + file.getAbsolutePath());
        }

        ScannerType scannerType = bridge.getType(file);

        if (scannerType == null) {
            throw new TypeParsingException();
        } else {
            return bridge.testScan(scannerType, file);
        }
    }

    @Transactional(readOnly = false) // used to be true
    public Scan getScan(@Nonnull String filePath) throws TypeParsingException, ScanTestingException {
        return getScan(new File(filePath));
    }

    @Transactional(readOnly = false) // used to be true
    public Scan getScan(@Nonnull File file) throws TypeParsingException, ScanTestingException, ScanFileNotFoundException {

        checkForUpdate();

        if (!file.exists()) {
            throw new ScanFileNotFoundException("Scan file not found: " + file.getAbsolutePath());
        }

        ScannerType scannerType = bridge.getType(file);

        if (scannerType == null) {
            throw new TypeParsingException();
        } else {
            ScanCheckResultBean resultBean = bridge.testScan(scannerType, file);

            if (resultBean.getScanCheckResult() == ScanImportStatus.SUCCESSFUL_SCAN) {
                return bridge.getScan(scannerType, file);
            } else {
                throw new ScanTestingException(resultBean.getScanCheckResult());
            }
        }
    }

    class ScanFileNotFoundException extends RuntimeException {
        public ScanFileNotFoundException(String message) {
            super(message);
        }
    }
    class TypeParsingException extends RuntimeException {}
    class ScanTestingException extends RuntimeException {
        public final ScanImportStatus status;

        ScanTestingException(ScanImportStatus status) {
            this.status = status;
        }
    }
}
