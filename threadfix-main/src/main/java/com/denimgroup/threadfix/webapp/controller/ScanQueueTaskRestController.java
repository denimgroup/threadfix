package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.ScanQueueService;

@Controller
@RequestMapping("/rest/tasks/")
public class ScanQueueTaskRestController extends RestController {
	
	public final static String OPERATION_QUEUE_SCAN = "queueScan";
	public final static String OPERATION_TASK_STATUS_UPDATE = "taskStatusUpdate";
	
	private ScanQueueService scanQueueService;
	
	@Autowired
	public ScanQueueTaskRestController(APIKeyService apiKeyService,
			ScanQueueService scanQueueService) {
		this.apiKeyService = apiKeyService;
		this.scanQueueService = scanQueueService;
	}
	
	/**
	 * Queue a new scan
	 * 
	 * @param applicationId
	 * @param scannerType
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="queueScan", method=RequestMethod.POST)
	public @ResponseBody Object queueScan(HttpServletRequest request,
			@RequestParam("applicationId") int applicationId,
			@RequestParam("scannerType") String scannerType) {
		
		int retVal = -1;
		
		log.info("Received REST request for a queueing a new " + scannerType
					+ " scan for applicationId " + applicationId);

		String result = checkKey(request, OPERATION_QUEUE_SCAN);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}

		retVal = scanQueueService.queueScan(applicationId, scannerType);
		
		return(retVal);
	}
	
	@RequestMapping(headers="Accept=application/json", value="taskStatusUpdate", method=RequestMethod.POST)
	public @ResponseBody Object taskStatusUpdate(HttpServletRequest request,
			@RequestParam("scanQueueTaskId") int scanQueueTaskId,
			@RequestParam("message") String message) {
		boolean retVal = false;
		
		log.info("Reeived a REST request to update the status of scan " + scanQueueTaskId);
		
		String result = checkKey(request, OPERATION_TASK_STATUS_UPDATE);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		retVal = this.scanQueueService.taskStatusUpdate(scanQueueTaskId, message);
		
		return(retVal);
	}
}
