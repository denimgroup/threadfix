package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.interop.ScanCheckResultBean;
import com.denimgroup.threadfix.importer.interop.ScanImportStatus;
import com.denimgroup.threadfix.importer.testutils.ScanFileUtils;
import org.junit.Test;
import org.mockito.InjectMocks;

import static org.junit.Assert.assertTrue;

public class ArachniTests {

    @InjectMocks
    ChannelImporter importer = new ArachniChannelImporter();

    @Test
    public void testArachniBasic() {

        importer.setChannel(new ApplicationChannel());

        importer.setFileName(ScanFileUtils.getFile("/Dynamic/Arachni/php-demo.xml"));

        ScanCheckResultBean resultBean = importer.checkFile();

        assertTrue("Result was " + resultBean.getScanCheckResult() + ", should have been success.",
                resultBean.getScanCheckResult().equals(ScanImportStatus.SUCCESSFUL_SCAN));
    }

}
