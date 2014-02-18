<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/newApplicationModalController.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/newTeamModalController.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/teams-page.js"></script>
</head>

<body id="apps">
	<h2>Applications</h2>

    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
        <div id="myTeamModal" class="modal hide fade" tabindex="-1"
                 role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
            <div ng-show='teams' id="formDiv">
                <%@ include file="/WEB-INF/views/organizations/newTeamForm.jsp" %>
            </div>
        </div>
    </security:authorize>

    <!-- Get the CSRF token so we can use it everywhere -->
    <spring:url value="/" var="emptyUrl"/>

    <div ng-controller="ApplicationsIndexController" ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">
        <div ng-hide='teams' style="text-align: center">
            {{ progressText }}
        </div>

        <div ng-show="successMessage" class="alert alert-success">
            <button class="close" data-dismiss="alert" type="button">x</button>
            {{ successMessage }}
        </div>

        <div ng-show="errorMessage" class="alert alert-success">
            <button class="close" data-dismiss="alert" type="button">x</button>
            {{ errorMessage }}
        </div>

        <%@ include file="/WEB-INF/views/organizations/indexTable.jsp" %>
    </div>

</body>
