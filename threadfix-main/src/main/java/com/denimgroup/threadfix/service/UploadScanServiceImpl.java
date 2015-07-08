package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.Collection;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Service
@Transactional
public class UploadScanServiceImpl implements UploadScanService{

    private final SanitizedLogger log = new SanitizedLogger(UploadScanServiceImpl.class);

    @Autowired
    private ScanTypeCalculationService scanTypeCalculationService;
    @Autowired
    private ScanService scanService;
    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private ScanMergeService scanMergeService;
    @Autowired
    private DefaultConfigService defaultConfigService;
    @Autowired
    private AcceptanceCriteriaStatusService acceptanceCriteriaStatusService;
    @Autowired
    private ApplicationService applicationService;

    @Override
    public Object processMultiFileUpload(Collection<MultipartFile> files, Integer orgId, Integer appId, String channelIdString) {
        if(files.isEmpty()){
            return failure("No files selected.");
        }

        if(appId == null){
            return failure("No appId");
        }

        Integer channelId = null;

        for(MultipartFile file : files){
            Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, channelIdString);

            if (myChannelId == null) {
                return failure("Failed to determine the scan type.");
            }

            if(channelId != null && !channelId.equals(myChannelId)){
                return failure("Scans are not of the same type.");
            }

            channelId = myChannelId;
        }

        List<String> fileNames = list(), originalNames = list();
        try {

            for(MultipartFile file : files){

                String fileName = scanTypeCalculationService.saveFile(channelId, file);

                fileNames.add(fileName);
                originalNames.add(file.getOriginalFilename());

                ScanCheckResultBean returnValue = scanService.checkFile(channelId, fileName);

                if(!ScanImportStatus.SUCCESSFUL_SCAN.equals(returnValue.getScanCheckResult())){
                    return failure(returnValue.getScanCheckResult().toString());
                }
            }

            Scan scan = scanMergeService.saveRemoteScanAndRun(channelId, fileNames, originalNames);

            if (scan != null) {
                if (orgId != null) {
                    Organization organization = organizationService.loadById(orgId);
                    return success(organization);
                } else {
                    return success(scan);
                }
            } else {
                return failure("Something went wrong while processing the scan.");
            }
        } finally {

            // only delete if the user hasn't set a directory
            if (!defaultConfigService.loadCurrentConfiguration().fileUploadLocationExists()) {
                if (!fileNames.isEmpty()) {
                    for (String fileName : fileNames) {
                        File diskFile = DiskUtils.getScratchFile(fileName);

                        if (diskFile.exists()) {
                            log.info("After scan upload, file is still present. Attempting to delete.");
                            boolean deletedSuccessfully = diskFile.delete();

                            if (deletedSuccessfully) {
                                log.info("Successfully deleted scan file.");
                            } else {
                                log.error("Unable to delete file.");
                            }
                        }
                    }
                }
            }

            acceptanceCriteriaStatusService.runStatusCheck(appId);
        }
    }
}
