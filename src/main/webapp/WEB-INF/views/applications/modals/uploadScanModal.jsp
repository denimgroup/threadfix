<%@ include file="/common/taglibs.jsp"%>

<a id="uploadScanModalLink" href="#uploadScan${ application.id }" role="button" class="btn" data-toggle="modal">Upload Scan</a>
<div id="uploadScan${ application.id }" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<button type="button" class="close" data-dismiss="modal"
			aria-hidden="true">X</button>
		<h4 id="myModalLabel"><c:out value="${ application.name }"/> Scan Upload</h4>
	</div>
	<div id="dtFormDiv">
		<%@ include file="/WEB-INF/views/applications/forms/uploadScanForm.jsp" %>
	</div>
</div>