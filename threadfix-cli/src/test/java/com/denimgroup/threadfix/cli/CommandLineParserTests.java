package com.denimgroup.threadfix.cli;

import junit.framework.TestCase;
import org.apache.commons.cli.Options;
import org.junit.Test;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/21/13
 * Time: 2:25 PM
 * To change this template use File | Settings | File Templates.
 */
public class CommandLineParserTests extends TestCase {

    @Test
    public void testGetOptions() {
        Options options = CommandLineParser.getOptions();
        assertEquals(16, options.getOptions().size());
    }
}
