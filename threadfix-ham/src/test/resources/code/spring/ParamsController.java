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
    public String home10(@RequestParam(required = false, defaultValue="test2", value="integer") Integer integer, Model model) {
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
}
