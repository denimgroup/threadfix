/** ====================================================================
 * jsPDF table plugin
 * Copyright (c) 2014 Nelli.Prashanth,https://github.com/Prashanth-Nelli
 * MIT LICENSE
 * ====================================================================
 */

( function(jsPDFAPI) {

var doc		= null;
var width	= 0;
var heigth	= 0;
var rowCount	= 0;
var nextStart	= 0;
var columnCount	= 0;
var pageStart	= 0;
var heights	= [];
var SplitIndex	= [];
var cSplitIndex = [];
var dimensions	= [];



var defaultConfig = {
	xstart : 20,
	ystart : 20,
	tablestart : 20,
	marginright : 20,
	xOffset : 10,
	yOffset : 10
};

//draws table on the document

jsPDFAPI.drawTable = function(table_DATA,config) {

	var i = 0;
	var j = 0;
	var tabledata = [];

	if (!config) {
		config = {};
	}

	for (var key in defaultConfig) {
		if (config[key]) {
			defaultConfig[key] = config[key];
		}
	}

	doc = this;
	
	pageStart = defaultConfig.tablestart;
	

	initPDF(table_DATA, defaultConfig, true);

	if ((dimensions[3] + defaultConfig.tablestart) > (doc.internal.pageSize.height)) {
		cSplitIndex = SplitIndex;
		cSplitIndex.push(table_DATA.length);
		for (; i < cSplitIndex.length; i++) {
			tabledata = [];
			tabledata = table_DATA.slice(j, cSplitIndex[i]);
			insertHeader(tabledata);
			pdf(tabledata, dimensions, true, false);
			pageStart = defaultConfig.ystart;
			initPDF(tabledata, defaultConfig, false);
			j = cSplitIndex[i];
			if ((i + 1) != cSplitIndex.length) {
				doc.addPage();
			}
		}
	} else {
		insertHeader(table_DATA)
		pdf(table_DATA, dimensions, true, false);
	}

	return nextStart;
};

//converts table to json

jsPDFAPI.tableToJson = function(id) {

	var i = 0;
	var j = 0;
	var obj = {};
	var data = [];
	var keys = [];
	var table = document.getElementById(id);
	var rows = table.rows;
	var noOfRows = rows.length;
	var noOfCells = table.rows[0].cells.length;

	for ( i = 0; i < noOfCells; i++) {
		keys.push(rows[0].cells[i].textContent);
	}

	for ( j = 0; j < noOfRows; j++) {
		obj = {};
		for ( i = 0; i < noOfCells; i++) {
			try {
				obj[keys[i]] = rows[j].cells[i].textContent.replace(/^\s+|\s+$/gm, '');
			} catch(ex) {
				obj[keys[i]] = '';
			}
		}
		data.push(obj);
	}
	return data.splice(1);
};

// Inserts Table Head row

function insertHeader(data) {
	
	var rObj = {};
	var hObj = {};
	rObj = data[0];
	for (var key in rObj) {
		hObj[key] = key;
	}
	data.unshift(hObj);
};

// intialize the dimension array, column count and row count

function initPDF(data, marginConfig, firstpage) {

	dimensions[0] = marginConfig.xstart;

	if (firstpage) {
		dimensions[1] = marginConfig.tablestart;
	} else {
		dimensions[1] = marginConfig.ystart;
	}

	dimensions[2] = doc.internal.pageSize.width - marginConfig.xstart - 20 - marginConfig.marginright;
	dimensions[3] = 250;
	dimensions[4] = marginConfig.ystart;
	dimensions[5] = marginConfig.marginright;
	dimensions[6] = marginConfig.xOffset || 5;
	dimensions[7] = marginConfig.yOffset || 5;

	columnCount = calColumnCount(data);
	rowCount = data.length;
	width = dimensions[2] / columnCount;
	height = dimensions[2] / rowCount;
	dimensions[3] = calculateDim(data, dimensions);

};

//calls methods in a sequence manner required to draw table

function pdf(table, dimensions, hControl, bControl) {
	
	columnCount = calColumnCount(table);
	rowCount = table.length;
	dimensions[3] = calculateDim(table, dimensions);
	width = dimensions[2] / columnCount;
	height = dimensions[2] / rowCount;
	drawRows(rowCount, dimensions, hControl);
	drawColumns(columnCount, dimensions);
	nextStart = insertData(rowCount, columnCount, dimensions, table, bControl);
	return nextStart;
};

//inserts text into the table

function insertData(rowCount, columnCount, dimensions, data, brControl) {
	
	var fontSize = doc.internal.getFontSize();
	var xOffset = defaultConfig.xOffset;
	var yOffset = defaultConfig.yOffset;
	var iTexts = 0;
	var cell = null;
	var start = 0;
	var end = 0;
	var obj = {};

	y = dimensions[1] + yOffset;

	for (var i = 0; i < rowCount; i++) {
		obj = data[i];
		x = dimensions[0] + xOffset;
		for (var key in obj) {
			if (obj.hasOwnProperty(key)) {

				cell = (obj[key] ? obj[key] : '-') + '';

				if (((cell.length * fontSize) + xOffset) > (width)) {
					iTexts = cell.length * fontSize;
					start = 0;
					end = 0;
					ih = 0;
					if ((brControl) && (i === 0)) {
						doc.setFont(doc.getFont().fontName, "bold");
					}
					for (var j = 0; j < iTexts; j++) {
						end += Math.floor(2 * width / fontSize) - Math.ceil(xOffset / fontSize);
						doc.text(x, y + ih, cell.substring(start, end));
						start = end;
						ih += fontSize;
					}
				} else {
					if ((brControl) && (i === 0)) {
						doc.setFont("times", "bold");
					}
					doc.text(x, y, cell);
				}
				x += dimensions[2] / columnCount;
			}
		}
		doc.setFont("times", "normal");
		y += heights[i];
	}
	return y;
};

//calculates no.of based on the data array

function calColumnCount(data) {
	
	var obj = data[0];
	var i = 0;
	for (var key in obj) {
		if (obj.hasOwnProperty(key)) {
			i += 1;
		}
	}
	return i;
};

//draws columns based on the caluclated dimensionsensions

function drawColumns(i, dimensions) {
	
	var x = dimensions[0];
	var y = dimensions[1];
	var w = dimensions[2] / i;
	var h = dimensions[3];

	for (var j = 0; j < i; j++) {
		doc.rect(x, y, w, h);
		x += w;
	}
};

//calculates dimensionsensions based on the data array and returns y position for further editing of document

function calculateDim(data, dimensions) {
	
	var row = 0;
	var x = dimensions[0];
	var y = dimensions[1];
	var fontSize = doc.internal.getFontSize();
	var noOfLines = 0;
	var indexHelper = 0;
	var lengths = [];

	heights = [];
	value = 0;
	SplitIndex = [];

	for (var i = 0; i < data.length; i++) {
		var obj = data[i];
		var length = 0;
		for (var key in obj) {
			if (obj[key] !== null) {
				if (length < obj[key].length) {
					lengths[row] = obj[key].length;
					length = lengths[row];
				}
			}
		}++row;
	}

	for (var i = 0; i < lengths.length; i++) {
		if ((lengths[i] * (fontSize)) > (width - dimensions[5])) {
			noOfLines = Math.ceil((lengths[i] * (fontSize)) / width);
			heights[i] = (noOfLines) * (fontSize / 2) + dimensions[6] + 10;
		} else {
			heights[i] = (fontSize + (fontSize / 2)) + dimensions[6] + 10;
		}
	}

	for (var i = 0; i < heights.length; i++) {
		value += heights[i];
		indexHelper += heights[i];
		if (indexHelper > (doc.internal.pageSize.height - pageStart)) {
			SplitIndex.push(i);
			indexHelper = 0;
			pageStart = dimensions[4] + 30;
		}
	}

	return value;
};

//draw rows based on the length of data array

function drawRows(i, dimensions, hrControl) {

	var x = dimensions[0];
	var y = dimensions[1];
	var w = dimensions[2];
	var h = dimensions[3] / i;

	for (var j = 0; j < i; j++) {
		if (j === 0 && hrControl) {
			doc.setFillColor(182, 192, 192);
			//colour combination for table header
			doc.rect(x, y, w, heights[j], 'F');
		} else {
			doc.setDrawColor(0, 0, 0);
			//colour combination for table borders you
			doc.rect(x, y, w, heights[j]);
		}
		y += heights[j];
	}
};
	

}(jsPDF.API));

