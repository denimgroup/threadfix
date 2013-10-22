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
	 * @throws RuntimeException
	 */
	public static Task convertJsonStringToTask(String jsonText) throws RuntimeException {
		Task retVal = null;
		
		try {
			retVal = new ObjectMapper().readValue(jsonText, Task.class);
		} catch (JsonParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return retVal;
	}
}
