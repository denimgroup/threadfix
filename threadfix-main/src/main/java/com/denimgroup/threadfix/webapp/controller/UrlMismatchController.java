package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.RequestUrlService;
import com.denimgroup.threadfix.webapp.config.CustomLoginSuccessHandler;

@Controller
@RequestMapping("/urlMismatch")
public class UrlMismatchController {

    protected final SanitizedLogger log = new SanitizedLogger(UrlMismatchController.class);

    @Autowired
    DefaultConfigService defaultConfigService;
    @Autowired
    RequestUrlService requestUrlService;

    @RequestMapping(method = RequestMethod.GET)
    public String urlMismatchPage(@RequestParam(value="redirect", required = false) String redirectUrl, HttpServletRequest request, Model model) {
        model.addAttribute("currentBaseUrl", requestUrlService.getBaseUrlFromRequest(request));
        model.addAttribute("savedBaseUrl", defaultConfigService.loadCurrentConfiguration().getBaseUrl());
        model.addAttribute("redirectUrl", redirectUrl);
        log.info(redirectUrl);
        return "urlMismatch";
    }
}
