<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/applications-index-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/upload-scan-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
</head>

<body id="apps">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

	<h2>Applications</h2>

    <%--<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">--%>
        <%--<div id="myTeamModal" class="modal hide fade" tabindex="-1"--%>
                 <%--role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">--%>
            <%--<div ng-show='teams' id="formDiv">--%>
                <%--<%@ include file="/WEB-INF/views/organizations/newTeamForm.jsp" %>--%>
            <%--</div>--%>
        <%--</div>--%>
    <%--</security:authorize>--%>

    <div ng-controller="ApplicationsIndexController">

        <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

        <c:if test="${ not empty successMessage }">
            <div class="alert alert-success">
                <button class="close" data-dismiss="alert" type="button">x</button>
                <c:out value="${ successMessage }"/>
            </div>
        </c:if>
        <%@ include file="/WEB-INF/views/successMessage.jspf" %>

        <div ng-show="errorMessage" class="alert alert-success">
            <button class="close" data-dismiss="errorMessage = false" type="button">x</button>
            {{ errorMessage }}
        </div>

        <%@ include file="/WEB-INF/views/organizations/indexTable.jsp" %>
    </div>

</body>
