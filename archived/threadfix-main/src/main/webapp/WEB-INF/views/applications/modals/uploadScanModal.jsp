<%@ include file="/common/taglibs.jsp"%>

<div id="uploadScan${ application.id }" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<h4 style="text-align:left;" id="myModalLabel">
			<span ng-non-bindable style="max-width:400px; display:inline-block; float:left" class="ellipsis"><c:out value="${ application.name }"/></span>
			 &nbsp;Scan Upload
		</h4>
	</div>
	<div id="scanFormDiv${ application.id }">
		<%@ include file="/WEB-INF/views/applications/forms/uploadScanForm.jsp" %>
	</div>
</div>
