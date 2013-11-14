package com.denimgroup.threadfix.framework.engine;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

public class ServletMappingTests {
    
    ////////////////////////////////////////////////////////////////
    ///////////////////////// Sample Data //////////////////////////
    ////////////////////////////////////////////////////////////////
    
    @NotNull
    List<ClassMapping> sampleServlets = makeClassMappings(
			// WebLogic examples
			// http://docs.oracle.com/cd/E13222_01/wls/docs92/webapp/configureservlet.html#wp156745
			"watermelon", "myservlets.watermelon",
			"garden", "myservlets.garden",
			"list", "myservlets.list",
			"kiwi", "myservlets.kiwi",
			
			// Servlet Specification
			// http://jcp.org/aboutJava/communityprocess/final/jsr315/
			
			"servlet1", "myservlets.servlet1",
			"servlet2", "myservlets.servlet2",
			"servlet3", "myservlets.servlet3",
			"servlet4", "myservlets.servlet4"
			);
	
	@NotNull
    List<UrlPatternMapping> sampleServletMappings = makeUrlPatternMappings(
			"watermelon", "/fruit/summer/*",
			"garden", "/seeds/*",
			"list", "/seedlist",
			"kiwi", "*.abc",
			
			"servlet1", "/foo/bar/*",
			"servlet2", "/baz/*",
			"servlet3", "/catalog",
			"servlet4", "*.bop");
    
    
    ////////////////////////////////////////////////////////////////
    ///////////////////////////// Tests ////////////////////////////
    ////////////////////////////////////////////////////////////////
    
	@Test
    public void testURLToClassMapping() throws IOException {
    	List<Entry<String,String>> tests;
    	
    	ServletMappings mappings = getTestMappings();
    	
    	tests = makeMappingsList(
    			"/fruit/summer/index.html", "myservlets.watermelon",
    			"/fruit/summer/index.abc", "myservlets.watermelon",
    			"/seedlist", "myservlets.list",
    			"/seedlist/pear.abc", "myservlets.kiwi",
    			"/seeds", "myservlets.garden",
    			"/seeds/index.html", "myservlets.garden",
    			"/index.abc", "myservlets.kiwi",
    			
    			"/foo/bar/index.html", "myservlets.servlet1",
    			"/foo/bar/index.bop", "myservlets.servlet1",
    			"/baz", "myservlets.servlet2",
    			"/baz/index.html", "myservlets.servlet2",
    			"/catalog", "myservlets.servlet3",
    			"/catalog/index.html", ServletMappings.DEFAULT_SERVLET,
    			"/catalog/racecar.bop", "myservlets.servlet4",
    			"/index.bop", "myservlets.servlet4"
    			);
    	
    	assertTrue("The wrong number of tests were present",
    			tests.size() == 15);
    	
    	for (Entry<String, String> entry : tests) {
    		String result = mappings.getClassForURL(entry.getKey());
    		String errorString = "Test failed for " + entry.getKey() + " -> " +
    				entry.getValue() + "\nActual result was " + result;
    		assertTrue(errorString, result.equals(entry.getValue()));
    	}
    }
    
	@Test
    public void testClassToURLMapping() throws IOException {
    	List<Entry<String,String>> tests;
    	
    	ServletMappings mappings = getTestMappings();
    	
    	tests = makeMappingsList(
    			"myservlets.watermelon", "/fruit/summer/*",
    			"myservlets.list", "/seedlist",
    			"myservlets.garden", "/seeds/*",
    			"myservlets.kiwi", "*.abc",
    			
    			"myservlets.servlet1", "/foo/bar/*",
    			"myservlets.servlet2", "/baz/*",
    			"myservlets.servlet3", "/catalog",
    			"myservlets.servlet4", "*.bop"
    		);
    	
    	assertTrue("The wrong number of tests were present",
    			tests.size() == 8);
    	
    	for (Entry<String, String> entry : tests) {
    		List<String> result = mappings.getURLPatternsForClass(entry.getKey());
    		boolean passed = result.get(0) != null && result.get(0).equals(entry.getValue());
    		assertTrue("Test failed for " + entry.getKey() + " -> " + entry.getValue() +
    				"\nResulting value was " + result.get(0), passed);
    	}
    }
	
	@Test(expected=NullPointerException.class)
	public void testUrlPatternMappingNullArgs() {
		new UrlPatternMapping(null, null);
	}
	
	@Test(expected=NullPointerException.class)
	public void testClassMappingNullArgs() {
		new ClassMapping(null, null, null);
	}

	@Test(expected=NullPointerException.class)
	public void testServletMappingNulls() {
        new ServletMappings(null, null, null);
	}

    ////////////////////////////////////////////////////////////////
    ///////////////////////////// Utils ////////////////////////////
    ////////////////////////////////////////////////////////////////

    private ServletMappings getTestMappings() throws IOException {
        return new ServletMappings(sampleServletMappings, sampleServlets, new ProjectDirectory(File.createTempFile("test", "test")));
    }

    @NotNull
    private Entry<String,String> entry(String key, String value) {
    	return new SimpleEntry<>(key, value);
    }

    @NotNull
    private List<Entry<String,String>> makeMappingsList(@NotNull String... strings) {
    	List<Entry<String,String>> mappings = new ArrayList<>();

    	for (int i = 0; i < strings.length - 1; i += 2) {
    		mappings.add(entry(strings[i], strings[i + 1]));
    	}

    	return mappings;
    }

    @NotNull
    private List<ClassMapping> makeClassMappings(@NotNull String... strings) {
    	List<ClassMapping> mappings = new ArrayList<>();
    	
    	for (int i = 0; i < strings.length - 1; i += 2) {
    		mappings.add(new ClassMapping(strings[i], strings[i + 1], null));
    	}
    	
    	return mappings;
    }
    
    @NotNull
    private List<UrlPatternMapping> makeUrlPatternMappings(@NotNull String... strings) {
    	List<UrlPatternMapping> mappings = new ArrayList<>();
    	
    	for (int i = 0; i < strings.length - 1; i += 2) {
    		mappings.add(new UrlPatternMapping(strings[i], strings[i + 1]));
    	}
    	
    	return mappings;
    }
}
