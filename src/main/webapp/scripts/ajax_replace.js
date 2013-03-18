function submitAjaxModal(url, formId, formDiv, successDiv, modalName) {
	$.ajax({
		type : "POST",
		url : url,
		data : $(formId).serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			
			if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
				$(formDiv).html(text);
			} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(modalName).on('hidden', function () {
					$(successDiv).html(text);
			    });
			    $(modalName).modal('hide');
			} else {
				try {
					var json = JSON.parse(text);
					alert(json.error);
				} catch (e) {
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
	return false;
}

function submitAjax(url, formId, formDiv, successDiv) {
	$.ajax({
		type : "POST",
		url : url,
		data : $(formId).serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			
			if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
				$(formDiv).html(text);
			} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(successDiv).html(text);
			} else {
				try {
					var json = JSON.parse(text);
					alert(json.error);
				} catch (e) {
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
	return false;
}

function basicGet(url, target) {
	$.ajax({
		type : "GET",
		url : url,
		dataType : "text",
		success : function(text) {
			if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(target).html(text);
			} else {
				try {
					var json = JSON.parse(text);
					alert(json.error);
				} catch (e) {
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
    return false;
}

function basicPost(url, formId, target) {
	$.ajax({
		type : "POST",
		url : url,
		data : $(formId).serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(target).html(text);
			} else {
				try {
					var json = JSON.parse(text);
					alert(json.error);
				} catch (e) {
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
		}
	});
	return false;
}

// These are for the application page.
function switchDTModals() {
    $("#addDefectTracker").modal('hide');
    $("#createDefectTracker").modal('show');
    return false;
};

function switchWafModals() {
    $("#addWaf").modal('hide');
    $("#createWaf").modal('show');
    return false;
};

function addWafAndRefresh(url) {
	return submitAjaxModal(url, '#addWafForm', '#addWaf', '#appWafDiv', '#addWaf');
}

function createWafAndRefresh(url) {
	return submitAjaxModal(url, '#wafForm', '#createWaf', '#appWafDiv', '#createWaf');
}

function updateWafAndRefresh(url, wafForm, editWafDiv) {
	return submitAjaxModal(url, wafForm, editWafDiv, '#appWafDiv', editWafDiv);
}

function updateDTAndRefresh(url, dtForm, dtWafDiv) {
	return submitAjaxModal(url, dtForm, dtWafDiv, '#defectTableDiv', dtWafDiv);
}

function switchTabs(url) {
	return basicGet(url, '#tabsDiv');
}

function createDTAndRefresh(url) {
	$.ajax({
		type : "POST",
		url : url,
		data : $('#createDefectTrackerForm').serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
				$('#dtFormDiv').html(text);
			} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$('#addDefectTracker').html(text);
				$('#defectTableDiv').html(text);
			    $('#createDefectTracker').modal('hide');
			    $('#addDefectTracker').modal('show');
			    
			} else {
				try {
					var json = JSON.parse(text);
					alert(json.error);
				} catch (e) {
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
    return false;
}

function addDTAndRefresh(url) {
	return submitAjaxModal(url, '#addDTForm', '#addDTFormDiv', '#appDTDiv', '#addDefectTracker');
}

function deleteKey(url) {
	if (confirm('Are you sure you want to delete this API Key?'))
		return basicPost(url, '#deleteForm', '#tableDiv');
	return false;
}

