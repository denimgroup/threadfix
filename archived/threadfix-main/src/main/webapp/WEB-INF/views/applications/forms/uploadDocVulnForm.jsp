<%--<%@ include file="/common/taglibs.jsp"%>--%>

<%--<spring:url value="/organizations/{orgId}/applications/{appId}/documents/vulnerabilities/{vulnId}/upload" var="uploadUrl">--%>
	<%--<spring:param name="orgId" value="${ vulnerability.application.organization.id }"/>--%>
	<%--<spring:param name="appId" value="${ vulnerability.application.id }"/>--%>
	<%--<spring:param name="vulnId" value="${ vulnerability.id }"/>--%>
<%--</spring:url>--%>
<%--<form:form id="docVulnForm${ vulnerability.id }" style="margin-bottom:0px" modelAttribute="application" method="post" autocomplete="off" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">--%>
	<%--<div class="modal-body">--%>
		<%--<div id="noDocVulnFound${ vulnerability.id }" class="alert alert-error" style="display:none;text-align:left;">--%>
			<%--<button class="close" type="button" onclick="javascript:$('#noScanFound${ vulnerability.id }').css('display','none');">�</button>--%>
			<%--Please select a file.--%>
		<%--</div>--%>
		<%--<c:if test="${ not empty message }">--%>
			<%--<div class="alert alert-error">--%>
				<%--<button class="close" data-dismiss="alert" type="button">�</button>--%>
				<%--<c:out value="${ message }"/>--%>
			<%--</div>--%>
		<%--</c:if>--%>
		<%----%>
		<%--<table>--%>

			<%--<tr>--%>
				<%--<td class="right-align" style="padding:5px;">File</td>--%>
				<%--<td class="left-align" style="padding:5px;"><input id="docVulnInput${ vulnerability.id }" type="file" name="file" size="50" /></td>--%>
			<%--</tr>--%>
		<%--</table>--%>
	<%--</div>--%>
	<%--<div class="modal-footer">--%>
		<%--<span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>--%>
		<%--<button id="closeDocVulnModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>--%>
		<%--<button id="submitDocVulnModal${ vulnerability.id }" onclick="javascript:submitAjaxScan('<c:out value="${uploadUrl }"/>','docVulnInput${ vulnerability.id }', '#docVulnFormDiv${ vulnerability.id }', 'noDocVulnFound${ vulnerability.id }');return false;" class="btn btn-primary">Upload</button>--%>
	<%--</div>--%>
<%--</form:form>--%>

<script type="text/ng-template" id="vulnDocForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Upload Document
        </h4>
    </div>

    <div ng-form="form" class="modal-body" ng-file-drop="onFileSelect($files)">

        <div ng-show="waiting" class="modal-loading"><div><span class="spinner dark"></span>Processing...</div></div><br>

        <progressbar ng-show="uploading" animate="false" value="dynamic" type="success"><b>{{uploadedPercent}}%</b></progressbar>

        <table ng-hide="waiting || uploading">
            <tr>
                <td class="right-align" style="padding:5px;">File</td>
                <td class="left-align" style="padding:5px;"><input id="docFileInput" type="file" name="file" size="50" ng-file-select="onFileSelect($files)"/></td>
            </tr>
        </table>
    </div>
    <div class="modal-footer">
        <span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>
        <a class="btn" ng-click="cancel()">Close</a>
    </div>
</script>
