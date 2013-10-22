page = 1;

var lastSort = 0;
var lastField = 0;

function refillElement(elementId, endPoint, page, login)
{
	refillElementSort(elementId, endPoint, page, null, login);
}

function refillElementDropDownPage(elementId, endPoint, login) {
	refillElement(elementId, endPoint, $("#pageInput").val(), login);
}

function refillElementDropDownPageRemoteProvider(elementId, endPoint, login, inputId) {
	refillElement(elementId, endPoint, $(inputId).val(), login);
}

function refillElementSort(elementId, endPoint, page, field, login)
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
	
	var caretState = false;
	if (field) {
		caretState = $('#headerCaret' + field).attr('class').indexOf('caret-up') == -1;
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
		data += ', "descriptionFilter" : ' + JSON.stringify($.trim($("#descriptionFilterInput").val()));
	} else {
		data += ', "descriptionFilter" : ""';
	}
	
	if (typeof($("#descriptionFilterInput").val()) != 'undefined') {
		data += ', "severityFilter" : ' + JSON.stringify($.trim($("#severityFilterInput").val()));
	} else {
		data += ', "severityFilter" : ""';
	}
	
	if (typeof($("#descriptionFilterInput").val()) != 'undefined') {
		data += ', "locationFilter" : ' + JSON.stringify($.trim($("#locationFilterInput").val()));
	} else {
		data += ', "locationFilter" : ""';
	}
		
	if (typeof($("#descriptionFilterInput").val()) != 'undefined') {
		data += ', "parameterFilter" : ' + JSON.stringify($.trim($("#parameterFilterInput").val()));
	} else {
		data += ', "parameterFilter" : ""';
	}
	
	if (typeof($("#cweFilterInput").val()) != 'undefined') {
		data += ', "cweFilter" : ' + JSON.stringify($.trim($("#cweFilterInput").val()));
	} else {
		data += ', "cweFilter" : ""';
	}
	
	data += "}";
	
	$.ajax({
		type : "POST",
		url : endPoint,
		data : data,
		contentType : "application/json",
		dataType : "text",
		success : function(text) {
			if (text.search('<head>') == -1) {
				$(elementId).html(text);
				
				var caret= '#headerCaret' + field;
				if (caretState) {
					$(caret).addClass('caret-up');
					$(caret).removeClass('caret-down');
				} else {
					$(caret).addClass('caret-down');
					$(caret).removeClass('caret-up');
				}
//				
//				if (addExpandsHandlers) {
//					addExpandsHandlers();
//				}

				if (modalRefreshFunctions) {
					for (var i = 0; i < modalRefreshFunctions.length; i++) {
						modalRefreshFunctions[i]();
					}
				}
			} else {
				// Kind of a hack
				alert('Logging out.');
				window.location = login;
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			// TODO show an error
	    }
	});
}

function toggleFilters(show, elementId, endPoint){
	if (show == true){
		$("#linksSpan").css('display','');
		$("#showFilters").css('display','none');
		$("#vulnerabilityFilters").css('display','');
		//clearFilters(elementId, endPoint);
	} else {
		$("#linksSpan").css('display','none');
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
	var checked = chkAll.attr("checked");
	var t = $("#" + tableId);
	var rows = t.find("tr");
	
	for(var k=1; k<rows.length; k++)
	{
		var checkbox = rows[k].children[cb_col].children[0];
		if (checkbox != null && checkbox.type == 'checkbox' && $(rows[k]).hasClass('bodyRow')) {  
			checkbox.checked = checked;
		} 
	}
}

addToDocumentReadyFunctions(function() {
	$(".refreshOnLoad").each(function() {
		refillElementSort('#' + $(this).attr("id"), $(this).attr("data-source-url"), 1, null, $(this).attr("data-login-url"));
	});
});
