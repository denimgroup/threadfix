<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{appId}/documents/upload" var="uploadUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="docForm${ application.id }" style="margin-bottom:0px" modelAttribute="application" method="post" autocomplete="off" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
	<div class="modal-body">
		<div id="noDocFound${ application.id }" class="alert alert-error" style="display:none;text-align:left;">
			<button class="close" type="button" onclick="javascript:$('#noScanFound${ application.id }').css('display','none');">×</button>
			Please select a file.
		</div>
		<c:if test="${ not empty message }">
			<div class="alert alert-error">
				<button class="close" data-dismiss="alert" type="button">×</button>
				<c:out value="${ message }"/>
			</div>
		</c:if>
		
		<table>

			<tr>
				<td class="right-align" style="padding:5px;">File</td>
				<td class="left-align" style="padding:5px;"><input id="docInput${ application.id }" type="file" name="file" size="50" /></td>
			</tr>
		</table>
	</div>
	<div class="modal-footer">
		<span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>
		<button id="closeDocModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<button id="submitDocModal${ application.id }" onclick="javascript:submitAjaxScan('<c:out value="${uploadUrl }"/>','docInput${ application.id }', '#docFormDiv${ application.id }', 'noDocFound${ application.id }');return false;" class="btn btn-primary">Upload</button>
	</div>
</form:form>
