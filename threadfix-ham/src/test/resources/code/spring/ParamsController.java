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

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.Locale;

@Controller
@RequestMapping(value = "test/")
public class ParamsController {

    @RequestMapping(value = "/1", method = RequestMethod.GET)
    public String home1(@RequestParam Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/2", method = RequestMethod.GET)
    public String home2(@RequestParam("integer") Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/3", method = RequestMethod.GET)
    public String home3(@RequestParam(value="integer") Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/4", method = RequestMethod.GET)
    public String home4(@RequestParam(value="integer", required=false) Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/5", method = RequestMethod.GET)
    public String home5(@RequestParam(required=false, value="integer") Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/6", method = RequestMethod.GET)
    public String home7(@RequestParam(defaultValue="test", value="integer") Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/8", method = RequestMethod.GET)
    public String home8(@RequestParam(defaultValue="test") Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/9", method = RequestMethod.GET)
    public String home9(@RequestParam(required=false) Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/10", method = RequestMethod.GET)
    public String home10(@RequestParam(required = false, defaultValue="test2", value = "integer") Integer integer547, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/11", method = RequestMethod.GET)
    public String home11(@RequestParam(required = false, defaultValue="test2") Integer integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/12", method = RequestMethod.GET)
    public String home12(@RequestParam(required = false, defaultValue="test2") @MaskFormat("###-####-###") String integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/13", method = RequestMethod.GET)
    public String home13(@RequestParam @MaskFormat("###-####-###") String integer, Model model) {
        SecurityContextHolder.getContext().getAuthentication().getName();
        return "config/index";
    }

    @RequestMapping(value = "/14", method = RequestMethod.GET)
    public String twitterCallback(
            @RequestParam(value = "integer", required = false) String oauthToken,
            Model model) throws JsonParseException, JsonMappingException, IOException {

        return "index";
    }
}
