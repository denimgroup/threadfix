package com.denimgroup.threadfix.importer.utils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Created by mac on 2/6/14.
 */
public class SimpleScan implements Iterable<SimpleFinding> {

    private final List<SimpleFinding> simpleFindings;

    public SimpleScan(List<SimpleFinding> simpleFindings) {
        this.simpleFindings = simpleFindings;
    }

    public List<SimpleFinding> getSimpleFindings() {
        return simpleFindings;
    }

    public static SimpleScan fromStringArray(String[][] strings) {
        List<SimpleFinding> findings = new ArrayList<>();
        for (String[] line : strings) {
            findings.add(new SimpleFinding(line));
        }
        return new SimpleScan(findings);
    }

    @Override
    public Iterator<SimpleFinding> iterator() {
        return simpleFindings.iterator();
    }
}
