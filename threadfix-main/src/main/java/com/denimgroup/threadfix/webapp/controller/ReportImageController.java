////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

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

        response.setHeader("Content-Type", "image/png");

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
