package com.denimgroup.threadfix.framework.engine;

import static com.denimgroup.threadfix.framework.TestConstants.BODGEIT_SOURCE_LOCATION;
import static com.denimgroup.threadfix.framework.TestConstants.BODGEIT_WEB_XML;
import static com.denimgroup.threadfix.framework.TestConstants.PETCLINIC_SOURCE_LOCATION;
import static com.denimgroup.threadfix.framework.TestConstants.PETCLINIC_WEB_XML;
import static com.denimgroup.threadfix.framework.TestConstants.WAVSEP_SOURCE_LOCATION;
import static com.denimgroup.threadfix.framework.TestConstants.WAVSEP_WEB_XML;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.jetbrains.annotations.Nullable;
import org.junit.Test;

import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.engine.ServletMappings;
import com.denimgroup.threadfix.framework.engine.WebXMLParser;
import com.denimgroup.threadfix.framework.enums.FrameworkType;

public class WebXMLParserTests {

    @Nullable
    ServletMappings vulnClinic = WebXMLParser.getServletMappings(new File(PETCLINIC_WEB_XML),
    		new ProjectDirectory(new File(PETCLINIC_SOURCE_LOCATION)));
	@Nullable
    ServletMappings wavsep = WebXMLParser.getServletMappings(new File(WAVSEP_WEB_XML),
    		new ProjectDirectory(new File(WAVSEP_SOURCE_LOCATION)));
	@Nullable
    ServletMappings bodgeIt = WebXMLParser.getServletMappings(new File(BODGEIT_WEB_XML),
    		new ProjectDirectory(new File(BODGEIT_SOURCE_LOCATION)));
	
    ////////////////////////////////////////////////////////////////
    ///////////////////////////// Tests ////////////////////////////
    ////////////////////////////////////////////////////////////////
    
	@Test
    public void testFindWebXML() {
    	String[]
    			sourceLocations = { PETCLINIC_SOURCE_LOCATION, WAVSEP_SOURCE_LOCATION, BODGEIT_SOURCE_LOCATION },
    			webXMLLocations = { PETCLINIC_WEB_XML, WAVSEP_WEB_XML, BODGEIT_WEB_XML };
    	
    	for (int i = 0; i < sourceLocations.length; i++) {
    		File projectDirectory = new File(sourceLocations[i]);
    		assertTrue(projectDirectory != null && projectDirectory.exists());
    		
    		File file = new ProjectDirectory(projectDirectory).findWebXML();
    		assertTrue(file.getName().equals("web.xml"));
    		
    		assertTrue(file.getAbsolutePath().equals(webXMLLocations[i]));
    	}
    }
    
    // TODO improve these tests.
    @Test
    public void testWebXMLParsing() {
    	assertTrue(vulnClinic.getClassMappings().size() == 2);
    	assertTrue(vulnClinic.getServletMappings().size() == 2);
    	
    	assertTrue(wavsep.getClassMappings().size() == 0);
    	assertTrue(wavsep.getServletMappings().size() == 0);
    	
    	assertTrue(bodgeIt.getClassMappings().size() == 0);
    	assertTrue(bodgeIt.getServletMappings().size() == 1);
    }
    
    @Test
    public void testTypeGuessing() {
    	assertTrue(vulnClinic.guessApplicationType() == FrameworkType.SPRING_MVC);
    	assertTrue(wavsep.guessApplicationType() == FrameworkType.JSP);
    	assertTrue(bodgeIt.guessApplicationType() == FrameworkType.JSP);
    }

    @Test(expected=NullPointerException.class)
    public void testNullInput() {
        new ProjectDirectory(null).findWebXML();
    }

    // This one is IllegalArgumentException because they wrote that into the SAXParser implementation
    @Test(expected=IllegalArgumentException.class)
    public void testNullInputWebXMLParser() {
        WebXMLParser.getServletMappings(null, null);
    }

    @Test
    public void testBadInput() {
    	File doesntExist = new File("This/path/doesnt/exist");

    	assertTrue(new ProjectDirectory(doesntExist).findWebXML() == null);
    	
    	
    }
}
