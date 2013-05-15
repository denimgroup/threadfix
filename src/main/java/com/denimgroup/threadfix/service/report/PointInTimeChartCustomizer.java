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
		
		PiePlot plot = (PiePlot) chart.getPlot();
		plot.setSectionPaint(4, new Color(0, 70, 120));
		plot.setSectionPaint(3, new Color(0, 70, 120));
		plot.setSectionPaint(2, new Color(189, 216, 77));
		plot.setSectionPaint(1, new Color(253, 224, 94));
		plot.setSectionPaint(0, new Color(219, 109, 29));
		
		PieSectionLabelGenerator generator = new StandardPieSectionLabelGenerator("{0}: {1} ({2})");
		plot.setLabelGenerator(generator);
		
		plot.setLabelBackgroundPaint(new Color(255,255,255));
		
		Font font = new Font(Font.SANS_SERIF, Font.PLAIN, 12);
		plot.setLabelFont(font);
	}

}
