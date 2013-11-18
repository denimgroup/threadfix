////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.webapp.controller;

import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Document;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.service.DocumentService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/documents")
public class DocumentController {
	
	public static final String SCANNER_TYPE_ERROR = "ThreadFix was unable to find a suitable " +
			"scanner type for the file. Please choose one from the list.";

	private PermissionService permissionService;
	private DocumentService documentService;
	
	private final SanitizedLogger log = new SanitizedLogger(UploadScanController.class);

	@Autowired
	public DocumentController(PermissionService permissionService,
			DocumentService documentService) {
		this.permissionService = permissionService;
		this.documentService = documentService;
	}
	
	public DocumentController(){}

	
	@RequestMapping(value = "/upload", method = RequestMethod.POST)
	public ModelAndView uploadSubmit(@PathVariable("appId") int appId, 
			@PathVariable("orgId") int orgId, HttpServletRequest request,
			@RequestParam("file") MultipartFile file) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)){
			return new ModelAndView("403");
		}				
		String fileName = documentService.saveFileToApp(appId, file);
		
		if (fileName == null || fileName.equals("")) {
			log.warn("Saving the document have failed. Returning to document upload page.");
			ModelAndView mav = new ModelAndView("ajaxFailureHarness");
			mav.addObject("message","Unable to save the document to the application.");
			mav.addObject("contentPage","applications/forms/uploadDocForm.jsp");
			return mav;
		}else {
			ControllerUtils.addSuccessMessage(request, 
					"The document was successfully added to the application.");
//			ControllerUtils.addItem(request, "checkForRefresh", 1);		
			ModelAndView mav = new ModelAndView("ajaxRedirectHarness");
			mav.addObject("contentPage","/organizations/" + orgId + "/applications/" + appId);
			return mav;		
		}
	}

	@RequestMapping(value = "/vulnerabilities/{vulnId}/upload", method = RequestMethod.POST)
	public ModelAndView uploadSubmitVuln(@PathVariable("appId") int appId, 
			@PathVariable("orgId") int orgId,
			@PathVariable("vulnId") int vulnId,
			HttpServletRequest request,
			@RequestParam("file") MultipartFile file) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)){
			return new ModelAndView("403");
		}
		String fileName = documentService.saveFileToVuln(vulnId, file);
		System.out.println(file.getContentType());
		if (fileName == null || fileName.equals("")) {
			log.warn("Saving the document have failed. Returning to document upload page.");
			ModelAndView mav = new ModelAndView("ajaxFailureHarness");
			mav.addObject("message","Unable to save the document to the vulnerability.");
			mav.addObject("contentPage","applications/forms/uploadDocVulnForm.jsp");
			return mav;
		}else {
//			ControllerUtils.addItem(request, "checkForRefresh", 1);		
			ModelAndView mav = new ModelAndView("ajaxRedirectHarness");
			mav.addObject("contentPage","/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnId);
			return mav;		

		}
	}

	@RequestMapping(value = "/{docId}/view", method = RequestMethod.GET)
	public String detailDocument(Model model,@PathVariable("orgId") Integer orgId, 
			@PathVariable("appId") Integer appId,
			@PathVariable("docId") Integer docId,
			HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException {

		if (!permissionService.isAuthorized(Permission.READ_ACCESS,orgId,appId)){
			return "403";
		}
		
		Document document = null;
		if (docId != null) {
			document = documentService.loadDocument(docId);
		}
		
		if (document == null) {
			if (orgId != null && appId != null)
				return "redirect:/organizations/" + orgId + "/applications/" + appId + "/documents";
			else if (orgId != null)
				return "redirect:/organizations/" + orgId;
			else
				return "redirect:/";
		}
		
		String contentType = document.getContentType();
//		if (contentType == null || contentType.contains("htm") || contentType.contains("js")) {
//			contentType = "text/plain";
//		}
		response.setContentType(contentType);
		if(contentType.equals(documentService.getContentTypeService().getDefaultType())){
			response.addHeader("Content-Disposition", "attachment; filename=\""+document.getName()+"."+document.getType()+"\"");
			response.setContentType("application/octet-stream");
		}
		response.addHeader("X-Content-Type-Options", "nosniff");
		InputStream in = document.getFile().getBinaryStream();
		ServletOutputStream out = response.getOutputStream();
		IOUtils.copy(in, out);
		in.close();
		out.flush();
		out.close();
		
		return null;
	}
	
	@RequestMapping(value = "/{docId}/download", method = RequestMethod.POST)
	public String downloadDocument(Model model,@PathVariable("orgId") Integer orgId, 
			@PathVariable("appId") Integer appId,
			@PathVariable("docId") Integer docId,
			HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException {
		
		if (!permissionService.isAuthorized(Permission.READ_ACCESS,orgId,appId)){
			return "403";
		}
		
		Document document = null;
		if (docId != null) {
			document = documentService.loadDocument(docId);
		}
		
		if (document == null) {
			if (orgId != null && appId != null)
				return "redirect:/organizations/" + orgId + "/applications/" + appId + "/documents";
			else if (orgId != null)
				return "redirect:/organizations/" + orgId;
			else
				return "redirect:/";
		}
		response.setHeader("Content-Disposition", "attachment; filename=\"" + document.getName()+ "." + document.getType() + "\"");
		response.setContentType(document.getContentType());
		InputStream in = document.getFile().getBinaryStream();
		ServletOutputStream out = response.getOutputStream();
		IOUtils.copy(in, out);
		in.close();
		out.flush();
		out.close();
		
		return null;
	}

	
	@RequestMapping(value = "/{docId}/delete", method = RequestMethod.POST)
	public String deleteDocument(@PathVariable("orgId") Integer orgId, 
			@PathVariable("appId") Integer appId,
			@PathVariable("docId") Integer docId,
			HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS,orgId,appId)){
			return "403";
		}
		
		Document document = null;
		if (docId != null) {
			document = documentService.loadDocument(docId);
		}
		
		if (document == null) {
			if (orgId != null && appId != null)
				return "redirect:/organizations/" + orgId + "/applications/" + appId + "/documents";
			else if (orgId != null)
				return "redirect:/organizations/" + orgId;
			else
				return "redirect:/";
		}
		
		String urlReturn = documentService.deleteDocument(document);
		
		return urlReturn;
	}
	

	
}
