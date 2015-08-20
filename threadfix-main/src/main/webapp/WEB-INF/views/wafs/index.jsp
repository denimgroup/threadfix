<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>WAFs</title>
    <cbs:cachebustscript src="/scripts/wafs-page-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
</head>

<body id="wafs" ng-controller="WafsPageController">

	<h2>WAFs</h2>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jspf" %>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="/WEB-INF/views/wafs/forms/editWafForm.jsp" %>
    <%@ include file="/WEB-INF/views/wafs/forms/createWafForm.jsp" %>

    <div id="helpText" style="width:630px;">
		A ThreadFix WAF is used to generate rules for a WAF or IDS/IPS program that is used to filter web traffic.
	</div>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <a ng-show="initialized" id="createWafModalButton" ng-click="openNewModal()" class="btn">Create WAF</a>

    <table ng-show="initialized" class="table table-striped">
        <thead>
            <tr>
                <th class="long first">Name</th>
                <th class="medium">Type</th>
                <th class="centered">Edit / Delete</th>
                <th class="centered last">Rules</th>
            </tr>
        </thead>
        <tbody id="wafTableBody">
            <tr ng-hide="wafs" class="bodyRow">
                <td colspan="5" style="text-align:center;">No WAFs found.</td>
            </tr>
            <tr ng-show="wafs" ng-repeat="waf in wafs" class="bodyRow">
                <td class="details" id="wafName{{ waf.name | removeSpace }}">
                    {{ waf.name }}
                </td>
                <td id="wafType{{ waf.name | removeSpace }}">
                    {{ waf.wafType.name }}
                </td>
                <td class="centered">
                    <a id="editWafModalButton{{ waf.name | removeSpace }}" ng-click="openEditModal(waf)" class="btn">Edit / Delete</a>
                </td>
                <td class="centered">
                    <spring:url value="/wafs/{wafId}" var="wafUrl">
                        <spring:param name="wafId" value="{{ waf.id }}" />
                    </spring:url>
                    <a id="rulesButton{{ waf.name | removeSpace }}" ng-click="goToWaf(waf)" role="button" class="btn">Rules</a>
                </td>
            </tr>
        </tbody>
    </table>
</body>
