package com.denimgroup.threadfix.service.report;

import java.awt.Color;

import net.sf.jasperreports.engine.JRChart;
import net.sf.jasperreports.engine.JRChartCustomizer;

import org.jfree.chart.JFreeChart;
import org.jfree.chart.labels.PieSectionLabelGenerator;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.PiePlot;

public class PointInTimeChartCustomizer implements JRChartCustomizer {

	@SuppressWarnings("deprecation")
	@Override
	public void customize(JFreeChart chart, JRChart jasperChart) {
		//<property name="PredefinedColors" value="Critical:#A63603;High:#E6550D;Medium:#FD8D3C;Low:#FDBE85;Information:#FEEDDE"/>

		//254, 237, 222; 253, 190, 133; 253, 141, 60; 230, 85, 13; 166, 54, 3; 
		PiePlot plot = (PiePlot) chart.getPlot();
		plot.setSectionPaint(0, new Color(166, 54, 3));
		plot.setSectionPaint(1, new Color(230, 85, 13));
		plot.setSectionPaint(2, new Color(253, 141, 60));
		plot.setSectionPaint(3, new Color(253, 190, 133));
		plot.setSectionPaint(4, new Color(254, 237, 222));
		
		PieSectionLabelGenerator generator = new StandardPieSectionLabelGenerator("{0}: {1} ({2})");
		plot.setLabelGenerator(generator);
		
		plot.setLabelBackgroundPaint(new Color(255,255,255));
	}

}
