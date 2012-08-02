page = 1;

var lastSort = 0;
var lastField = 0;

function refillElement(elementId, endPoint, page)
{
	refillElementSort(elementId,endPoint,page,null);
}

function refillElementDropDownPage(elementId, endPoint) {
	refillElementSort(elementId, endPoint, $("#pageInput").val());
}

function refillElementSort(elementId, endPoint, page, field)
{
	sort = 1;
	
	if (lastField === 0 && field !== 0) {
		page = 1;
	}
	
	if (field != null && field !== 0 && field === lastField) {
		if (lastSort === 1) {
			sort = 2;
		}
	}
	
	lastField = field;
	lastSort = sort;

	if (typeof(page) == "number") {
		data = '{ "page" : ' + page;
	} else if (typeof(page) == "string" && /^[0-9]+$/.test(page)) {
		data = '{ "page" : ' + page;
	}
	
	if (field) {
		data += ', "field": ' + field;
	} else {
		sort = 0;
	}
	
	if (sort) {
		data += ', "sort": ' + sort;
	}
	
	if (typeof($("#descriptionFilterInput").val()) != 'undefined') {
		data += ', "descriptionFilter" : "' + $("#descriptionFilterInput").val() + '"';
	}
	
	if (typeof($("#descriptionFilterInput").val()) != 'undefined') {
		data += ', "severityFilter" : "' + $("#severityFilterInput").val() + '"';
	}
	
	if (typeof($("#descriptionFilterInput").val()) != 'undefined') {
		data += ', "locationFilter" : "' + $("#locationFilterInput").val() + '"';
	}
		
	if (typeof($("#descriptionFilterInput").val()) != 'undefined') {
		data += ', "parameterFilter" : "' + $("#parameterFilterInput").val() + '"';
	}
	
	data += "}";
	
	$.ajax({
		type : "POST",
		url : endPoint,
		data : data,
		contentType : "application/json",
		dataType : "text",
		success : function(text) {
			$(elementId).html(text);
		},
		error : function (xhr, ajaxOptions, thrownError){
			alert("Request for table data failed.");
	    }
	});
}

function toggleFilters(show, elementId, endPoint){
	if (show == true){
		$("#showFilters").css('display','none');
		$("#vulnerabilityFilters").css('display','');
		//clearFilters(elementId, endPoint);
	} else {
		$("#showFilters").css('display','');
		$("#vulnerabilityFilters").css('display','none');
		clearFilters(elementId, endPoint);
	}
}

function clearFilters(elementId, endPoint){
	$("#severityFilterInput").val("");
	$("#locationFilterInput").val("");
	$("#parameterFilterInput").val("");
	$("#descriptionFilterInput").val("");
	if (elementId !== null && endPoint !== null) {
		filter(elementId, endPoint);
	}
}

function filter(elementId, endPoint) {
	// By switching them here they should be the same after the switch in refillElement
	if (lastField != null && lastField !== 0) {
		if (lastSort === 1) {
			lastSort = 2;
		} else {
			lastSort = 1;
		}
	}
	refillElement(elementId, endPoint, 1, lastField);
}

function ToggleCheckboxes(tableId, cb_col){
	var chkAll = $("#chkSelectAll");
	var checked = chkAll.checked;
	var t = $("#" + tableId);
	var rows = t.getElementsByTagName("tr");
	
	for(var k=1; k<rows.length - 1; k++)
	{
		var checkbox = rows[k].children[cb_col].children[0];
		if (checkbox != null && checkbox.type == 'checkbox' && $(rows[k]).hasClass('bodyRow')) {  
			checkbox.checked = checked;
		} 
	}
}
