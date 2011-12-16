$(document).ready(function() {
					$("#jsonLink").click(
							function() {
								var button = $(this);
								var form = $(this);
								
								var key = document.getElementById('apikey').innerHTML;
																
								if (key === '') {
									key = $("#apikey").val();
								}
								
								$.ajax({
									type : "POST",
									url : form.attr("href"),
									contentType : "application/json",
									data : key,
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
	showResponse("success", '<pre>' + text + '</pre>', element);
};

showErrorResponse = function showErrorResponse(text, element) {
	showResponse("error", text, element);
};

showResponse = function(type, text, element) {
	$('#results').html(text);
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