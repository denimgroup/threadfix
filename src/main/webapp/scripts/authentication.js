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

					$("#jsonLink").click(
							function() {
								var form = $(this);
								var button = $(this);
								var defectTracker = $("option:selected",
										"#defectTrackerId").val();
								var userName = $("#username")
										.val();
								var password = $("#password")
										.val();
								var projectName = $("#projectname").val();
								$.ajax({
									type : "POST",
									url : form.attr("href"),
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
								return false;
							});
				});

showSuccessResponse = function(text, element) {
	showResponse("success", text, element);
};

showErrorResponse = function showErrorResponse(text, element) {
	showResponse("error", text, element);
};

showResponse = function(type, text, element) {
	var product_array = text.split(",");
	var html;
	
	if (product_array[0] == 'Authentication failed') {
		html = 'Authentication failed';
		$('#projectList').html('');
		$('#projectList').attr("disabled","disabled");
	} else {
		html = 'Connection successful';
		$('#projectList').html('');
		$('#projectList').removeAttr("disabled");
		for ( var i = 0; i < product_array.length; i++) {
			$('#projectList').append(
					'<option value="' + product_array[i] + '">'
							+ product_array[i] + '</option>');
		}
	}
	var responseElementId = element.attr("id") + "Response";
	var responseElement = $("#" + responseElementId);
	if (responseElement.length == 0) {
		responseElement = $(
				'<span id="' + responseElementId + '" class="' + type
						+ '" style="display:none"> <em id="jsonResult">' + html
						+ '</em> </span>').insertAfter(element);
	} else {
		responseElement.replaceWith('<span id="' + responseElementId
				+ '" class="' + type + '" style="display:none"> <em id="jsonResult2" >' + html
				+ '</em> </span>');
		responseElement = $("#" + responseElementId);
	}
	responseElement.fadeIn("slow");
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