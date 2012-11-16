package com.denimgroup.threadfix.webapp.controller;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.AccessControlMapService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.viewmodels.AccessControlMapModel;

@Controller
@RequestMapping("/configuration/users/{userId}/access")
public class AccessControlMapController {
	
	protected final SanitizedLogger log = new SanitizedLogger(AccessControlMapController.class);
	
	private AccessControlMapService accessControlMapService;
	private UserService userService;
	
	@Autowired
	public AccessControlMapController(UserService userService,
			AccessControlMapService accessControlMapService) {
		this.accessControlMapService = accessControlMapService;
		this.userService = userService;
	}
	
	@RequestMapping(value="/new", method = RequestMethod.POST)
	public String createMapping(@PathVariable("userId") int userId, 
			@ModelAttribute AccessControlMapModel accessControlModel,
			Model model, HttpServletResponse response) {

		User user = userService.loadUser(userId);
		if (user == null) {
			throw new ResourceNotFoundException();
		}
		
		accessControlModel.setUserId(userId);
		AccessControlTeamMap map =
				accessControlMapService.parseAccessControlTeamMap(accessControlModel);
		map.setUser(user);
		
		String error = accessControlMapService.validateMap(map, null);
		if (error != null) {
			writeResponse(response,error);
		} else {
			accessControlMapService.store(map);
			return returnTable(model, userId);
		}
		return null;
	}
	
	private String returnTable(Model model, Integer userId) {
		model.addAttribute("maps", accessControlMapService.loadAllMapsForUser(userId));
		return "config/users/permTable";
	}
	
	private void writeResponse(HttpServletResponse response, String error) {
		if (error != null) {
			response.setContentType("application/json");
	        String json = "{\"error\": \"" + error + "\"}";
	        PrintWriter out = null;
			try {
				out = response.getWriter();
				out.write(json);
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				if (out != null) {
					out.close();
				}
			}
		}
	}
	
	@RequestMapping(value="/{mapId}/edit", method = RequestMethod.POST)
	public String editMapping(@ModelAttribute AccessControlMapModel accessControlModel,
			@PathVariable("userId") int userId, 
			@PathVariable("mapId") int mapId, 
			HttpServletRequest request, HttpServletResponse response,
			Model model) {
		
		User user = userService.loadUser(userId);
		if (user == null) {
			throw new ResourceNotFoundException();
		}
		
		accessControlModel.setUserId(userId);
		AccessControlTeamMap map =
				accessControlMapService.parseAccessControlTeamMap(accessControlModel);
		map.setUser(user);

		String error = accessControlMapService.validateMap(map, mapId);
		if (error != null) {
			writeResponse(response,error);
		} else {
			
			accessControlMapService.deactivate(accessControlMapService.loadAccessControlTeamMap(mapId));
			accessControlMapService.store(map);
			return returnTable(model, userId);
		}
		
		return null;
	}
	
	@RequestMapping(value="/team/{mapId}/delete", method = RequestMethod.POST)
	public String deleteTeamMapping(@PathVariable("userId") int userId, 
			@PathVariable("mapId") int mapId, 
			HttpServletRequest request, Model model) {
		AccessControlTeamMap map = accessControlMapService.loadAccessControlTeamMap(mapId);
		accessControlMapService.deactivate(map);
		return returnTable(model, userId);
	}
	
	@RequestMapping(value="/app/{mapId}/delete", method = RequestMethod.POST)
	public String deleteAppMapping(@PathVariable("userId") int userId, 
			@PathVariable("mapId") int mapId, 
			HttpServletRequest request, Model model) {
		AccessControlApplicationMap map = accessControlMapService.loadAccessControlApplicationMap(mapId);
		accessControlMapService.deactivate(map);
		return returnTable(model, userId);
	}
}
