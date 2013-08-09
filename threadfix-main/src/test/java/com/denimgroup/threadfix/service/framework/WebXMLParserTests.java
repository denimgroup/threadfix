package com.denimgroup.threadfix.service.framework;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import com.denimgroup.threadfix.service.merge.FrameworkType;

public class WebXMLParserTests {

    // TODO move these to the src/test/resources folder and use that
    private String testRoot = "C:\\test\\projects\\";
    private String[] extensions = 
    	{ "spring-petclinic", "wavsep", "webgoat_src" };
    
    private String[] results = {
		"C:\\test\\projects\\spring-petclinic\\src\\main\\webapp\\WEB-INF\\web.xml",
		"C:\\test\\projects\\wavsep\\trunk\\WebContent\\WEB-INF\\web.xml",
		"C:\\test\\projects\\webgoat_src\\src\\main\\webapp\\WEB-INF\\web.xml"
    };
    
    ServletMappings vulnClinic = WebXMLParser.getServletMappings(new File(results[0]), 
    		new ProjectDirectory(new File("C:\\test\\projects\\spring-petclinic")));
	ServletMappings wavsep = WebXMLParser.getServletMappings(new File(results[1]), null);
	ServletMappings webGoat = WebXMLParser.getServletMappings(new File(results[2]), null);
	
    ////////////////////////////////////////////////////////////////
    ///////////////////////////// Tests ////////////////////////////
    ////////////////////////////////////////////////////////////////
    
    public void testFindWebXML()
    {
    	for (int i = 0; i < extensions.length; i++) {
    		File projectDirectory = new File(testRoot + extensions[i]);
    		assertTrue(projectDirectory != null && projectDirectory.exists());
    		
    		File file = new ProjectDirectory(projectDirectory).findWebXML();
    		assertTrue(file.getName().equals("web.xml"));
    		
    		assertTrue(file.getAbsolutePath().equals(results[i]));
    	}
    }
    
    // TODO improve these tests.
    @Test
    public void testWebXMLParsing() {
    	assertTrue(vulnClinic.getClassMappings().size() == 2);
    	assertTrue(vulnClinic.getServletMappings().size() == 2);
    	
    	assertTrue(wavsep.getClassMappings().size() == 0);
    	assertTrue(wavsep.getServletMappings().size() == 0);
    	
    	assertTrue(webGoat.getClassMappings().size() == 7);
    	assertTrue(webGoat.getServletMappings().size() == 8);
    }
    
    @Test
    public void testTypeGuessing() {
    	assertTrue(vulnClinic.guessApplicationType() == FrameworkType.SPRING_MVC);
    	assertTrue(wavsep.guessApplicationType() == FrameworkType.JSP);
    	assertTrue(webGoat.guessApplicationType() == FrameworkType.JSP);
    }
    
    @Test
    public void testBadInput() {
    	assertTrue(new ProjectDirectory(null).findWebXML() == null);
    	ServletMappings nullInputMappings = WebXMLParser.getServletMappings(null, null);
    	assertTrue(nullInputMappings != null);
    	assertTrue(nullInputMappings.getClassMappings() == null);
    	assertTrue(nullInputMappings.getServletMappings() == null);
    	
    	File doesntExist = new File("This/path/doesnt/exist");
    	
    	assertTrue(new ProjectDirectory(doesntExist).findWebXML() == null);
    	
    	
    }
}
