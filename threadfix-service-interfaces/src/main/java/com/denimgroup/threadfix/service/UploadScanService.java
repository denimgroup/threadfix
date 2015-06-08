package com.denimgroup.threadfix.service;

import org.springframework.web.multipart.MultipartFile;

import java.util.Collection;

public interface UploadScanService {

    Object processMultiFileUpload(Collection<MultipartFile> files, Integer orgId, Integer appId,
                                  String channelIdString);
}
