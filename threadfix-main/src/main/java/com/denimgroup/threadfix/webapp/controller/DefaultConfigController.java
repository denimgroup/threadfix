package com.denimgroup.threadfix.webapp.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.plugin.ldap.LdapServiceDelegateFactory;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Controller
@RequestMapping("/configuration/defaults")
@SessionAttributes("defaultConfiguration")
public class DefaultConfigController {
	
	protected final SanitizedLogger log = new SanitizedLogger(DefaultConfigController.class);

	private RoleService roleService = null;
	private DefaultConfigService defaultConfigService = null;
	
	@Autowired
	public DefaultConfigController(DefaultConfigService defaultConfigService,
			RoleService roleService) {
		this.roleService = roleService;
		this.defaultConfigService = defaultConfigService;
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		if (LdapServiceDelegateFactory.isEnterprise()){
			dataBinder.setAllowedFields("defaultRoleId", "globalGroupEnabled", "activeDirectoryBase",
                    "activeDirectoryURL", "activeDirectoryUsername", "activeDirectoryCredentials");
		} else {
			dataBinder.setAllowedFields("defaultRoleId", "globalGroupEnabled");
		}
	}
	
	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(Model model, HttpServletRequest request) {
		model.addAttribute("ldap_plugin",LdapServiceDelegateFactory.isEnterprise());
		model.addAttribute("defaultConfiguration", defaultConfigService.loadCurrentConfiguration());
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		return "config/defaults";
	}
	
	@RequestMapping(method = RequestMethod.POST)
	public String processForm(@ModelAttribute DefaultConfiguration configModel,
			HttpServletRequest request) {
		
		defaultConfigService.saveConfiguration(configModel);
		ControllerUtils.addSuccessMessage(request, "Configuration was saved successfully.");
		
		return "redirect:/configuration/defaults";
	}
	
}
