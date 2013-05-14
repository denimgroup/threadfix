<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{appId}/scans/upload" var="uploadUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="scanForm${ application.id }" style="margin-bottom:0px" modelAttribute="application" method="post" autocomplete="off" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
	<div class="modal-body">
		<c:if test="${ not empty message }">
			<div class="alert alert-error">
				<button class="close" data-dismiss="alert" type="button">×</button>
				<c:out value="${ message }"/>
			</div>
			<c:if test="${ not empty type }">
				<br>This error could be caused by trying to upload a scan in an incorrect format.
				<br>The last scan was uploaded to the channel <c:out value="${ type.name }"/>
				<br><c:out value="${ type.exportInfo }"/>
			</c:if>
		</c:if>
		
		<table>
		<c:if test="${ showTypeSelect }">
			<tr>
				<td class="right-align" style="padding:5px;">File Type</td>
				<td class="left-align"  style="padding:5px;">
					<select id="channelSelect${ application.id }" name="channelId">
					<option onclick="display(-1)" value="-1">Auto-detect</option>
						<c:forEach var="channel" items="${ channelTypes }">
							<option onclick="display(<c:out value="${ channel.id }"/>)" value="${ channel.id }"><c:out value="${ channel.name }"/></option>
						</c:forEach>
					</select>
					<c:forEach var="channel" items="${ channelTypes }">
						<c:if test="${ not empty channel.exportInfo }">
							<span style="padding-left: 8px; display: none;" id="info${ channel.id }">
								<a href="javascript:alert('<c:out value='${ channel.exportInfo }'/>');">Which file format do I need?</a>
							</span>
						</c:if>
					</c:forEach>
				</td>
			</tr>
		</c:if>
			<tr>
				<td class="right-align" style="padding:5px;">File</td>
				<td class="left-align" style="padding:5px;"><input id="fileInput${ application.id }" type="file" name="file" size="50" /></td>
			</tr>
		</table>
	</div>
	<div class="modal-footer">
		<span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>
		<button id="closeScanModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<button id="submitScanModal${ application.id }" onclick="javascript:submitAjaxScan('<c:out value="${uploadUrl }"/>','fileInput${ application.id }', '#scanFormDiv${ application.id }', 'channelSelect${ application.id }');return false;" class="btn btn-primary">Upload Scan</button>
	</div>
</form:form>
