package com.denimgroup.threadfix.webapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/login.jsp")
public class LoginRedirectController {

	@RequestMapping(";jsessionid={id}")
	public String processLinkDelete(@PathVariable("id") String id) {
		return "redirect:/login.jsp";
	}
}
