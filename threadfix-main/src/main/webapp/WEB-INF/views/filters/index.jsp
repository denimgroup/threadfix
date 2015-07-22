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
        <%@ include file="/WEB-INF/views/filters/channelFilterForm.jsp"%>

        <ul ng-show="originalType !== 'Global'" class="breadcrumb">
            <li><a href="<spring:url value="/"/>">Applications Index</a> <span class="divider">/</span></li>

            <li ng-show="originalType === 'Application'"><a class="pointer" ng-click="goToTeam(organization)">Team: {{ application.team.name }}</a> <span class="divider">/</span></li>
            <li ng-show="originalType === 'Application'"><a class="pointer" ng-click="goToApp(organization, application)">Application: {{ application.name }}</a><span class="divider">/</span></li>

            <li ng-show="originalType === 'Organization'"><a class="pointer" ng-click="goToTeam(organization)">Team: {{ organization.name }}</a> <span class="divider">/</span></li>

            <li class="active">Vulnerability Filters</li>
        </ul>

        <h2 ng-show="tab.application">Application {{ application.name }} Filters</h2>
        <h2 ng-show="tab.organization">Team {{ organization.name }} Filters</h2>
        <h2 ng-show="tab.global">Global Filters</h2>

        <div id="helpText">
            ThreadFix Vulnerability Filters are used to sort data.<br/>
        </div>

        <tabset ng-hide="originalType === 'Global'">
            <tab ng-click="setTab('Application')" ng-show="originalType === 'Application'" heading="Application Filters" active="tab.application"></tab>
            <tab ng-click="setTab('Organization')" heading="Team Filters" active="tab.organization"></tab>
            <tab ng-click="setTab('Global')" heading="Global Filters" active="tab.global"></tab>
        </tabset>

        <div id="tabsDiv">
            <h3>{{ vulnFiltersTitle }}</h3>

            <div id="vulnFiltersSuccessMessage" ng-show="successMessage" class="alert alert-success">
                <button class="close" ng-click="successMessage = undefined" type="button">&times;</button>
                {{ successMessage }}
            </div>

            <a id="createNewKeyModalButton" ng-click="showNewFilterModal()" class="btn">Create New Filter</a>

            <div id="tableDiv">
                <%@ include file="/WEB-INF/views/filters/table.jsp" %>
            </div>

            <c:if test="${ isEnterprise}">
                <!-- Channel Vulnerability Filter section -->
                <div ng-show="originalType === 'Global' || type === 'Global'">
                    <h3>{{ channelVulnFiltersTitle }}</h3>

                    <div id="channelVulnFiltersSuccessMessage" ng-show="channelVulnSuccessMessage" class="alert alert-success">
                        <button class="close" ng-click="channelVulnSuccessMessage = undefined" type="button">&times;</button>
                        {{ channelVulnSuccessMessage }}
                    </div>

                    <a id="createNewChannelVulnModalButton" ng-click="showNewChannelVulnFilterModal()" class="btn">Create New Channel Vulnerability Filter</a>

                    <div id="tableChannelVulnDiv">
                        <%@ include file="/WEB-INF/views/filters/channelVulnTable.jsp" %>
                    </div>
                </div>
                <!-- End Channel Vulnerability Filter section -->
            </c:if>
            <h3>{{ severityFiltersTitle }}</h3>

            <%@ include file="/WEB-INF/views/filters/severityFilterForm.jsp" %>
        </div>
    </div>
</body>
