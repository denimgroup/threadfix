package com.denimgroup.threadfix.scanagent.util;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.denimgroup.threadfix.data.entities.Task;

public class JsonUtils {

	/**
	 * 
	 * @param jsonText
	 * @return
	 * @throws Exception 
	 * @throws RuntimeException
	 */
	public static Task convertJsonStringToTask(String jsonText) throws Exception {
		Task retVal = null;
		
		
			try {
				retVal = new ObjectMapper().readValue(jsonText, Task.class);
			} catch (JsonParseException e) {
				throw e;
			} catch (JsonMappingException e) {
				throw e;
			} catch (IOException e) {
				throw e;
			}
		
		return retVal;
	}
}
