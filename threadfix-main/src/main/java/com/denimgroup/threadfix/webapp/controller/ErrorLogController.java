package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;

import com.denimgroup.threadfix.service.util.ControllerUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.service.ExceptionLogService;

@Controller
@RequestMapping("/configuration/logs")
@PreAuthorize("hasRole('ROLE_CAN_VIEW_ERROR_LOGS')")
public class ErrorLogController {
	
	public ErrorLogController(){}
	
	@Autowired
	ExceptionLogService exceptionLogService;
	
	@RequestMapping(method = RequestMethod.GET)
	public String manageUsers(ModelMap model, HttpServletRequest request) {
		model.addAttribute("logId", ControllerUtils.getItem(request, "logId"));
		model.addAttribute("exceptionLogList", exceptionLogService.loadAll());
		return "config/logs";
	}
	
	@RequestMapping(value="/{logId}", method = RequestMethod.GET)
	public String manageUsers(ModelMap model, HttpServletRequest request,
			@PathVariable("logId") int logId) {
		ControllerUtils.addItem(request, "logId", logId);
		return "redirect:/configuration/logs";
	}
}
