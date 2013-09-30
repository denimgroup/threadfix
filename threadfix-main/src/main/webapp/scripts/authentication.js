$(document).ready(
	function() {
		var element = document.getElementById("defectTrackerId");
		var text = element.options[element.selectedIndex].text;	
		var element2 = document.getElementById("projectList");
		
		if (text == "<none>") {
			$("#username").attr("disabled", "disabled");
			$("#password").attr("disabled", "disabled");
			$('#projectList').html('');
			$("#projectList").attr("disabled", "disabled");
		}
		
		if (element2.length === 0) {
			$("#projectList").attr("disabled", "disabled");
			$('#projectList').html('');
		}
		var src;

		$("#defectTrackerId")
			.change(
				function() {
					var src = $("option:selected", this)
							.val();
					var text = $("option:selected", this)
							.text();
					if (src == 0 && text == "<none>") {
						$("#username").attr("disabled", "disabled");
						$("#password").attr("disabled", "disabled");
						$("#projectList").attr("disabled", "disabled");
					} else {
						$("#username").removeAttr("disabled");
						$("#password").removeAttr("disabled");
						$("#projectname").html("Product Name:");
					}
				});
	});

function jsonTest(url) {
	form = $("#jsonLink");
	button = $("#jsonLink");
	var defectTracker = $("option:selected",
			"#defectTrackerId").val();
	var userName = $("#username")
			.val();
	var password = $("#password")
			.val();
	
	if (password === "this is not the password") {
		showErrorResponse('{"message" : "Default Password", "error" : ' +
				'"You must re-enter your password to change the product." } ', button);
		return;
	}
	var projectName = $("#projectname").val();
	$.ajax({
		type : "POST",
		url : url,
		data : "{ \"defectTrackerId\": \""
				+ defectTracker
				+ "\",\"userName\": \"" + userName
				+ "\", \"password\": \"" + password
				+ "\", \"projectName\": \""
				+ projectName + "\" }",
		contentType : "application/json",
		dataType : "text",
		success : function(text) {
			showSuccessResponse(text,
					button);
		},
		error : function(xhr) {
			showErrorResponse(
					xhr.responseText, button);
		}
	});
	return;
}

showSuccessResponse = function(text, element) {
	showResponse("success", text, element);
};

showErrorResponse = function showErrorResponse(text, element) {
	showResponse("error", text, element);
};

showResponse = function(type, text, element) {
	var message = '', html = '';
	
	if (text === 'Authentication failed') {
		html = text;
		$('#projectList').html('');
		$('#projectList').attr("disabled","disabled");
	} else {
		try
		{
		   var json = $.parseJSON(text);
		   message = json.message;
		   
		   if (message === "Default Password") {
				html = json.error;
		   } else if (message === "Authentication failed") {
				html = json.error;
			} else {
				
				if (/^\s+$/.test(json.names)) {
					html = 'No Products available';
				} else {
					html = 'Connection successful';
					$('#projectList').html('');
					$('#projectList').removeAttr("disabled");
					$('#jsonLink').css("display","none");
					$('#submitDTModal').css("display","");
					
					var product_array = json.names.split(",");
					for ( var i = 0; i < product_array.length; i++) {
						$('#projectList').append(
								'<option value="' + product_array[i] + '">'
										+ product_array[i] + '</option>');
					}
				}
			}
		}
		catch(e)
		{
		   message = "Something went wrong";
		   $('#projectList').html('');
		   $('#projectList').attr("disabled","disabled");
		   html = "Something went wrong. This error is sometimes caused by an incomplete TFS configuration (<a target=\"_blank\" href=\"http://code.google.com/p/threadfix/wiki/DefectTrackers#Microsoft_TFS\">wiki page</a>). Check the error logs or contact your administrator for more information.";
		}
	}
	
	var responseElement = $("#jsonResult");
	var responseText = '';
	if (responseElement.length == 0) {
		if(html=='Connection successful'){
			responseText = '<div class="alert alert-success" id="jsonResult">' + html + '</div>';
		}else{
			responseText = '<div class="alert alert-error" id="jsonResult">' + html + '</div>';
		}
	} else {
		if(html=='Connection successful'){
			responseText = '<div class="alert alert-success" id="jsonResult2">' + html + '</div>';
		}else{
			responseText = '<div class="alert alert-error" id="jsonResult2">' + html + '</div>';
		}
	}
	
	var toReplaceDiv = $("#toReplaceDT");
	
	toReplaceDiv.css("display","none");
	
	toReplaceDiv.html(responseText);
	
	toReplaceDiv.fadeIn("slow");
};

xmlencode = function(xml) {
	// for IE
	var text;
	if (window.ActiveXObject) {
		text = xml.xml;
	}
	// for Mozilla, Firefox, Opera, etc.
	else {
		text = (new XMLSerializer()).serializeToString(xml);
	}
	return text.replace(/\&/g, '&' + 'amp;').replace(/</g, '&' + 'lt;')
			.replace(/>/g, '&' + 'gt;').replace(/\'/g, '&' + 'apos;').replace(
					/\"/g, '&' + 'quot;');
};
