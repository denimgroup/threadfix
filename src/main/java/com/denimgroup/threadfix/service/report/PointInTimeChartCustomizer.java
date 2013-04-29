package com.denimgroup.threadfix.service.report;

import java.awt.Color;
import java.awt.Font;

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
		
//		<seriesColor seriesOrder="0" color="#c4e3f3"/>
//		<seriesColor seriesOrder="1" color="#d0e9c6"/>
//		<seriesColor seriesOrder="2" color="#faf2cc"/>
//		<seriesColor seriesOrder="3" color="#EBCCCC"/>
		
		//254, 237, 222; 253, 190, 133; 253, 141, 60; 230, 85, 13; 166, 54, 3; 
		PiePlot plot = (PiePlot) chart.getPlot();
		plot.setSectionPaint(4, new Color(196, 227, 243));
		plot.setSectionPaint(3, new Color(196, 227, 243));
		plot.setSectionPaint(2, new Color(208, 233, 198));
		plot.setSectionPaint(1, new Color(250, 242, 204));
		plot.setSectionPaint(0, new Color(235, 204, 204));
		
		PieSectionLabelGenerator generator = new StandardPieSectionLabelGenerator("{0}: {1} ({2})");
		plot.setLabelGenerator(generator);
		
		plot.setLabelBackgroundPaint(new Color(255,255,255));
		
		Font font = new Font(Font.SANS_SERIF, Font.PLAIN, 12);
		plot.setLabelFont(font);
	}

}
