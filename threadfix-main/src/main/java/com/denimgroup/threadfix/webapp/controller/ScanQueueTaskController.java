package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.ScanQueueService;

@Controller
@RequestMapping("/configuration/scanqueue")
public class ScanQueueTaskController {

	private ScanQueueService scanQueueService;
	
	@Autowired
	public ScanQueueTaskController(ScanQueueService scanQueueService) {
		this.scanQueueService = scanQueueService;
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index(HttpServletRequest request, Model model) {
		model.addAttribute("scanQueueTaskList", scanQueueService.loadAll());
		
		
		return "config/scanqueue/index";
	}
}
