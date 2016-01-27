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

package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.RequestUrlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;

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
