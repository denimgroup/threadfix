package com.denimgroup.threadfix.webapp.controller;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.logging.SanitizedLogger;

@Controller
@RequestMapping("/jasperimage")
@PreAuthorize("hasRole('ROLE_CAN_GENERATE_REPORTS')")
public class ReportImageController {
	
	private final SanitizedLogger log = new SanitizedLogger(ReportImageController.class);
	
	/**
	 * This method is used to push report images to the browser from session memory.
	 * It currently erases images as they are retrieved, but could modified to cache them.
	 * A better map naming scheme would be necessary in that case.
	 */
	@RequestMapping(value="/{mapKey}/{imageKey}", method = RequestMethod.GET)
	public String getImage(@PathVariable String mapKey, @PathVariable String imageKey,
			HttpServletRequest request, 
			HttpServletResponse response) {
		
		InputStream imageStream = null;
		
		if (request.getSession().getAttribute(mapKey) != null) {
			Object value = request.getSession().getAttribute(mapKey);
			if (value instanceof Map<?,?>) {
				Map<?, ?> map = (Map<?, ?>) value;
				if (map.containsKey(imageKey)) {
					Object image = map.get(imageKey);
					if (image instanceof byte[]) {
						byte[] imageBytes = (byte[]) image;
						imageStream = new ByteArrayInputStream(imageBytes);
					}
					
					map.remove(imageKey);
					if (map.size() == 0) {
						request.getSession().removeAttribute(mapKey);
					}
				}
			}
		}
		
		if (imageStream != null) {
			// Java 7 try-with-resources
			try (ServletOutputStream out = response.getOutputStream()) {
				byte[] outputByteBuffer = new byte[65535];
				
				int remainingSize;
				
				remainingSize = imageStream.read(outputByteBuffer, 0, 65535);
				
				// copy binary content to output stream
				while (remainingSize != -1) {
					out.write(outputByteBuffer, 0, remainingSize);
					remainingSize = imageStream.read(outputByteBuffer, 0, 65535);
				}
				
				out.flush();
				return null;
			} catch (IOException e) {
				log.error("IOException encountered while trying to export an image.", e);
			} finally {
				try {
					imageStream.close();
				} catch (IOException e) {
					log.error("IOException encountered while trying to close the image stream.", e);
				}
			}
		}
			
		log.error("Unable to find report image.");
		return null;
	}
}
