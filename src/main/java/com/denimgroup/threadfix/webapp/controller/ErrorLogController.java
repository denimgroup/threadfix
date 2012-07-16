package com.denimgroup.threadfix.webapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.service.ExceptionLogService;

@Controller
@RequestMapping("/configuration/logs")
public class ErrorLogController {
	
	@Autowired
	ExceptionLogService exceptionLogService;
	
	@RequestMapping(method = RequestMethod.GET)
	public String manageUsers(ModelMap model) {
		model.addAttribute("exceptionLogList", exceptionLogService.loadAll());
		return "config/logs";
	}
}
