////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.DocumentDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Document;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.sql.rowset.serial.SerialBlob;
import java.io.IOException;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Service
@Transactional(readOnly = false)
public class DocumentServiceImpl implements DocumentService {
	
	private final SanitizedLogger log = new SanitizedLogger(DocumentService.class);
	
	private ApplicationDao applicationDao;
	private VulnerabilityService vulnerabilityService;
	private DocumentDao documentDao;
	private ContentTypeServiceImpl contentTypeService = new ContentTypeServiceImpl();
	
	@Autowired
	public DocumentServiceImpl(DocumentDao documentDao,
			ApplicationDao applicationDao,
			VulnerabilityService vulnerabilityService) {
		this.documentDao = documentDao;
		this.applicationDao = applicationDao;
		this.vulnerabilityService = vulnerabilityService;
	}

	/**
	 * Save a file associated with an app and use the default filename from the MultipartFile
	 * 
	 * @param appId ID for the app to attach the file to
	 * @param file file to associate with app
	 * @return filename that was saved
	 */
	@Override
	public Document saveFileToApp(Integer appId, MultipartFile file) {
		return saveFileToApp(appId, file, null);
	}
	
	
	/**
	 * Save a file associated with an app with a given filename
	 * 
	 * @param appId ID for the app to attach the file to
	 * @param file file to associate with app
	 * @param overrideFilename filename to use for the file (versus the default filename in the MultipartFile)
	 * @return filename that was saved
	 */
	@Override
	public Document saveFileToApp(Integer appId, MultipartFile file, String overrideFilename) {
		if (appId == null || file == null) {
			log.warn("The document upload file failed to save, it had null input.");
			return null;
		}
		
		Application application = applicationDao.retrieveById(appId);
		
		if (application == null) {
			log.warn("Unable to retrieve Application - document save failed.");
			return null;
		}
		
		if (!contentTypeService.isValidUpload(file.getContentType())){
			log.warn("Invalid filetype for upload: "+file.getContentType());
			return null;
		}
		
		Document doc = new Document();
		String fileFullName;
		
		if(overrideFilename != null) {
			fileFullName = overrideFilename;
		} else {
			fileFullName = file.getOriginalFilename();
		}
		doc.setApplication(application);
		doc.setName(getFileName(fileFullName));
		doc.setType(getFileType(fileFullName));
		if(!doc.getType().equals("json")){
			doc.setContentType(contentTypeService.translateContentType(file.getContentType()));	
		}else{
			doc.setContentType(contentTypeService.translateContentType("json"));
		}

		try {
			Blob blob = new SerialBlob(file.getBytes());
			doc.setFile(blob);

			List<Document> appDocs = application.getDocuments();
			if (appDocs == null) {
				appDocs = list();
			}
			appDocs.add(doc);
			
			documentDao.saveOrUpdate(doc);
			applicationDao.saveOrUpdate(application);

		} catch (SQLException | IOException e) {
			log.warn("Unable to save document - exception occurs.");
			return null;
		}
		
		return doc;
	}

	@Override
	public Document saveFileToVuln(Integer vulnId, MultipartFile file) {
		if (vulnId == null || file == null) {
			log.warn("The document upload file failed to save, it had null input.");
			return null;
		}
		
		if (!contentTypeService.isValidUpload(file.getContentType())){
			log.warn("Invalid filetype for upload: "+file.getContentType());
			return null;
		}
		
		Vulnerability vulnerability = vulnerabilityService.loadVulnerability(vulnId);
		
		if (vulnerability == null) {
			log.warn("Unable to retrieve Vulnerability - document save failed.");
			return null;
		}
		
		Document doc = new Document();
		String fileFullName = file.getOriginalFilename();
		doc.setVulnerability(vulnerability);
		doc.setName(getFileName(fileFullName));
		doc.setType(getFileType(fileFullName));
		doc.setContentType(contentTypeService.translateContentType(file.getContentType()));
		try {
			Blob blob = new SerialBlob(file.getBytes());
			doc.setFile(blob);

			List<Document> appDocs = vulnerability.getDocuments();
			if (appDocs == null) 
				appDocs = list();
			appDocs.add(doc);
			
			documentDao.saveOrUpdate(doc);
			vulnerabilityService.storeVulnerability(vulnerability);

		} catch (SQLException | IOException e) {
			log.warn("Unable to save document - exception occurs.");
			return null;
		}
		
		return doc;
	}

	@Override
	public Document loadDocument(Integer docId) {
		return documentDao.retrieveById(docId);
	}

	@Override
	public String deleteDocument(Document document) {
		
		if (document.getApplication() != null && document.getApplication().getId() != null ) {
			Application application = applicationDao.retrieveById(document.getApplication().getId());
			application.getDocuments().remove(document);
			document.setApplication(null);
			documentDao.delete(document);
			applicationDao.saveOrUpdate(application);
			return "redirect:/organizations/" + application.getOrganization().getId() + "/applications/" + application.getId();
		}
		
		if (document.getVulnerability() != null && document.getVulnerability().getId() != null ) {
			Vulnerability vulnerability = vulnerabilityService.loadVulnerability(document.getVulnerability().getId());
			vulnerability.getDocuments().remove(document);
			document.setVulnerability(null);
			documentDao.delete(document);
			vulnerabilityService.storeVulnerability(vulnerability);
			return "redirect:/organizations/" + vulnerability.getApplication().getOrganization().getId() + "/applications/" + vulnerability.getApplication().getId() + "/vulnerabilities/" + vulnerability.getId();
		}
		
		return null;
		
	}
	@Override
	public ContentTypeService getContentTypeService(){
		return contentTypeService;
	}
	
	private String getFileName(String fullName) {
		return FilenameUtils.getBaseName(fullName);
	}
	
	private String getFileType(String fullName) {
		return FilenameUtils.getExtension(fullName);
	}
	
}
