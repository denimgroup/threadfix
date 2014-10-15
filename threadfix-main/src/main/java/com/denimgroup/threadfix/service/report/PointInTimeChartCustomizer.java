////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.service.report;

import net.sf.jasperreports.engine.JRChart;
import net.sf.jasperreports.engine.JRChartCustomizer;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.labels.PieSectionLabelGenerator;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.PiePlot;

import java.awt.*;

public class PointInTimeChartCustomizer implements JRChartCustomizer {

	@SuppressWarnings("deprecation")
	@Override
	public void customize(JFreeChart chart, JRChart jasperChart) {

        //var vulnTypeColorList = ["#014B6E  ", "#458A37  ", "#EFD20A  ", "#F27421  ", "#F7280C  "];

		PiePlot plot = (PiePlot) chart.getPlot();
		plot.setSectionPaint(4, new Color(1, 75, 110));
		plot.setSectionPaint(3, new Color(69, 138, 55));
		plot.setSectionPaint(2, new Color(239, 210, 10));
		plot.setSectionPaint(1, new Color(242, 116, 33));
		plot.setSectionPaint(0, new Color(247, 40, 12));
		
		PieSectionLabelGenerator generator = new StandardPieSectionLabelGenerator("{0}: {1} ({2})");
		plot.setLabelGenerator(generator);
		
		plot.setLabelBackgroundPaint(new Color(255,255,255));
		
		Font font = new Font(Font.SANS_SERIF, Font.PLAIN, 12);
		plot.setLabelFont(font);
	}

}
