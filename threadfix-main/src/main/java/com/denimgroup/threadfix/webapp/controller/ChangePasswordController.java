package com.denimgroup.threadfix.webapp.controller;

import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.validator.UserValidator;

@Controller
@RequestMapping("/configuration/users/password")
@SessionAttributes("user")
public class ChangePasswordController {

	private UserService userService = null;
	private RoleService roleService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(EditUserController.class);

	@Autowired
	public ChangePasswordController(RoleService roleService,
			UserService userService) {
		this.userService = userService;
		this.roleService = roleService;
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("currentPassword", "unencryptedPassword", "passwordConfirm");
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView editForm(HttpServletRequest request) {
		
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		
		User user = null;
		
		Object successMessage = ControllerUtils.getSuccessMessage(request);
		
		if (userName != null){
			user = userService.loadUser(userName);
		}
		
		if (user == null) {
			log.warn(ResourceNotFoundException.getLogMessage("User", userName));
			throw new ResourceNotFoundException();
		}
				
		ModelAndView mav = new ModelAndView("config/users/password");
		mav.addObject(user);
		mav.addObject("successMessage", successMessage);
		return mav;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processEdit(@ModelAttribute User user,
			BindingResult result, SessionStatus status, HttpServletRequest request) {
		new UserValidator(roleService).validate(user, result);
		if (result.hasErrors()) {
			return "config/users/password";
		} else {
			
			if (user.getUnencryptedPassword() == null || 
					user.getUnencryptedPassword().trim().equals("")) {
				result.rejectValue("password", null, "You must enter a new password.");
				return "config/users/password";
			}
			
			String currentUserName = SecurityContextHolder.getContext().getAuthentication().getName();
			
			User databaseUser = userService.loadUser(user.getName());
			if (databaseUser != null && !databaseUser.getId().equals(user.getId())) {
				// TODO check this out
				result.rejectValue("currentPassword", "The user has changed since starting this procedure.");
				return "config/users/password";
			}
			
			if (userService.isCorrectPassword(databaseUser, user.getCurrentPassword())) {
				user.setHasChangedInitialPassword(true);
				user.setLastPasswordChangedDate(new Date());
				Object currentUserObject = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
				if (currentUserObject instanceof ThreadFixUserDetails) {
					ThreadFixUserDetails details = (ThreadFixUserDetails) currentUserObject;
					details.setHasChangedInitialPassword(true);
				}
				userService.storeUser(user);
				status.setComplete();
				log.info("The User " + currentUserName + " has completed the password change.");
				ControllerUtils.addSuccessMessage(request, "The password change was successful.");
				return "redirect:/configuration/users/password";
				
			} else {
				log.info("An incorrect password was submitted during a password change attempt.");
				result.rejectValue("currentPassword", null,"That was not the correct password.");
				return "config/users/password";
			}
		}
	}
	
}
