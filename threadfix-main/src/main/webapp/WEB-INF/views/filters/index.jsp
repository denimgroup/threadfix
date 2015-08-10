<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Filters</title>
	<cbs:cachebustscript src="/scripts/vulnerability-filters-controller.js"/>
	<cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
</head>

<body ng-controller="VulnerabilityFiltersController">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <div ng-show="initialized">
        <%@ include file="/WEB-INF/views/filters/form.jsp"%>

        <ul ng-if="originalType !== 'Global'" class="breadcrumb">
            <li><a href="<spring:url value="/"/>">Applications Index</a> <span class="divider">/</span></li>

            <li ng-show="originalType === 'Application'"><a class="pointer" ng-click="goToTeam(organization)">Team: {{ application.team.name }}</a> <span class="divider">/</span></li>
            <li ng-show="originalType === 'Application'"><a class="pointer" ng-click="goToApp(organization, application)">Application: {{ application.name }}</a><span class="divider">/</span></li>

            <li ng-show="originalType === 'Organization'"><a class="pointer" ng-click="goToTeam(organization)">Team: {{ organization.name }}</a> <span class="divider">/</span></li>

            <li class="active">Customize ThreadFix Vulnerability Types</li>
        </ul>

        <h2 ng-show="tab.application">Customize Vulnerability Types for Application {{ application.name }}</h2>
        <h2 ng-show="tab.organization">Customize Vulnerability Types for Team {{ organization.name }}</h2>
        <h2 ng-show="tab.global">Customize Global Vulnerability Types</h2>

        <tabset ng-hide="originalType === 'Global'">
            <tab ng-click="setTab('Application')" ng-show="originalType === 'Application'" heading="Application" active="tab.application"></tab>
            <tab ng-click="setTab('Organization')" heading="Team" active="tab.organization"></tab>
            <tab ng-click="setTab('Global')" heading="Global" active="tab.global"></tab>
        </tabset>

        <div id="tabsDiv">
            <div id="vulnFiltersSuccessMessage" ng-show="successMessage" class="alert alert-success">
                <button class="close" ng-click="successMessage = undefined" type="button">&times;</button>
                {{ successMessage }}
            </div>

            <a id="createNewKeyModalButton" ng-click="showNewFilterModal()" class="btn">Create New Mapping</a>

            <div id="tableDiv">
                <%@ include file="/WEB-INF/views/filters/table.jsp" %>
            </div>

            <h3>{{ severityFiltersTitle }}</h3>

            <%@ include file="/WEB-INF/views/filters/severityFilterForm.jsp" %>
        </div>
    </div>
</body>
