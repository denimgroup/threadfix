package com.denimgroup.threadfix.framework;

import static org.junit.Assert.assertTrue;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import org.junit.Test;

import com.denimgroup.threadfix.framework.engine.ClassMapping;
import com.denimgroup.threadfix.framework.engine.ServletMappings;
import com.denimgroup.threadfix.framework.engine.UrlPatternMapping;

public class ServletMappingTests {
    
    ////////////////////////////////////////////////////////////////
    ///////////////////////// Sample Data //////////////////////////
    ////////////////////////////////////////////////////////////////
    
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
    public void testURLToClassMapping()
    {
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
    		assertTrue(errorString, result != null && result.equals(entry.getValue()));
    	}
    }
    
	@Test
    public void testClassToURLMapping()
    {
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
    		boolean passed = result != null && result.get(0) != null && result.get(0).equals(entry.getValue());
    		assertTrue("Test failed for " + entry.getKey() + " -> " + entry.getValue() +
    				"\nResulting value was " + result.get(0), passed);
    	}
    }
	
	@Test(expected=IllegalArgumentException.class)
	public void testUrlPatternMappingNullArgs() {
		new UrlPatternMapping(null, null);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testClassMappingNullArgs() {
		new ClassMapping(null, null, null);
	}
    
    // TODO improve this test
	@Test
    public void testBadInput() {
    	ServletMappings nullAndNull = new ServletMappings(null, null, null);
    	ServletMappings somethingAndNull = new ServletMappings(sampleServletMappings, null, null);
    	ServletMappings nullAndSomething = new ServletMappings(null, sampleServlets, null);
    	ServletMappings emptyAndEmpty = new ServletMappings(new ArrayList<UrlPatternMapping>(), new ArrayList<ClassMapping>(), null);
    	
    	ServletMappings[] mappingsArray = { nullAndNull, somethingAndNull, nullAndSomething, emptyAndEmpty };
    	
    	String[] tests = {
    			"/fruit/summer/index.html",
    			"/fruit/summer/index.abc",
    			"/seedlist",
    			"/seedlist/pear.abc",
    			"/seeds",
    			"/seeds/index.html",
    			"/index.abc",
    			"/foo/bar/index.html",
    			"/foo/bar/index.bop",
    			"/baz",
    			"/baz/index.html",
    			"/catalog",
    			"/catalog/index.html",
    			"/catalog/racecar.bop",
    			"/index.bop",
    		};
    	
    	for (String string : tests) {
    		for (ServletMappings mappings : mappingsArray) {
	    		assertTrue(mappings.getClassForURL(string).equals(ServletMappings.DEFAULT_SERVLET));
    		}
    	}
    	
    	for (ServletMappings mappings : mappingsArray) {
    		assertTrue(mappings.getClassForURL(null).equals(ServletMappings.DEFAULT_SERVLET));
    	}
    	
    	for (ServletMappings mappings : mappingsArray) {
    		assertTrue(mappings.getURLPatternsForClass(null) != null && nullAndNull.getURLPatternsForClass(null).size() == 0);
    	}
    	
    	ServletMappings testMappings = getTestMappings();
    	
    	assertTrue(testMappings.getURLPatternsForClass(null) != null && nullAndNull.getURLPatternsForClass(null).size() == 0);
    	assertTrue(testMappings.getClassForURL(null).equals(ServletMappings.DEFAULT_SERVLET));
    }
    
    ////////////////////////////////////////////////////////////////
    ///////////////////////////// Utils ////////////////////////////
    ////////////////////////////////////////////////////////////////
    
    private ServletMappings getTestMappings() {
    	return new ServletMappings(sampleServletMappings, sampleServlets, null);
    }
    
    private Entry<String,String> entry(String key, String value) {
    	return new SimpleEntry<>(key, value);
    }
    
    private List<Entry<String,String>> makeMappingsList(String... strings) {
    	List<Entry<String,String>> mappings = new ArrayList<>();
    	
    	for (int i = 0; i < strings.length - 1; i += 2) {
    		mappings.add(entry(strings[i], strings[i + 1]));
    	}
    	
    	return mappings;
    }
    
    private List<ClassMapping> makeClassMappings(String... strings) {
    	List<ClassMapping> mappings = new ArrayList<>();
    	
    	for (int i = 0; i < strings.length - 1; i += 2) {
    		mappings.add(new ClassMapping(strings[i], strings[i + 1], null));
    	}
    	
    	return mappings;
    }
    
    private List<UrlPatternMapping> makeUrlPatternMappings(String... strings) {
    	List<UrlPatternMapping> mappings = new ArrayList<>();
    	
    	for (int i = 0; i < strings.length - 1; i += 2) {
    		mappings.add(new UrlPatternMapping(strings[i], strings[i + 1]));
    	}
    	
    	return mappings;
    }
}
