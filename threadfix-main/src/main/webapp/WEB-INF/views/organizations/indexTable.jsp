
<div style="padding-bottom:10px">
    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
        <a id="addTeamModalButton" ng-click="openTeamModal()" class="btn">Add Team</a>
    </security:authorize>
    <a ng-show="teams" class="btn" id="expandAllButton" ng-click="expand()">Expand All</a>
    <a ng-show="teams" class="btn" id="collapseAllButton" ng-click="contract()">Collapse All</a>
</div>

<table ng-show="teams" class="table table-hover white-inner-table"
        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
            ng-init="canCreateTeams = true"
        </security:authorize>
        >
    <%@ include file="/WEB-INF/views/applications/forms/newApplicationForm.jsp" %>
    <%@ include file="/WEB-INF/views/applications/forms/uploadScanForm.jsp" %>
    <%@ include file="/WEB-INF/views/organizations/newTeamForm.jsp" %>
    <thead>
    <tr>
        <th style="width:8px"></th>
        <th style="width:98px;">Name</th>
        <th class="centered fixed-team-header">Total</th>
        <th class="centered fixed-team-header">Critical</th>
        <th class="centered fixed-team-header">High</th>
        <th class="centered fixed-team-header">Medium</th>
        <th class="centered fixed-team-header">Low</th>
        <th class="centered fixed-team-header">Info</th>
        <th></th>
        <th style="width:130px;"></th>
        <th style="width:70px;"></th>
    </tr>
    </thead>
    <tbody>
        <tr ng-repeat-start="team in teams" id="teamRow{{ team.id }}" class="pointer" data-target-div="teamInfoDiv{{ team.id }}"
                data-caret-div="caret{{ team.id }}" data-report-div="reportDiv{{ team.id }}">
            <td id="teamCaret{{ team.name }}" ng-click="toggle(team)">
                <span ng-class="{ expanded: team.expanded }" class="caret-right"></span>
            </td>
            <td ng-click="toggle(team)" id="teamName{{ team.name }}">
                <div style="word-wrap: break-word;width:300px;text-align:left;">{{ team.name }}</div>
            </td>
            <td class="centered" ng-click="toggle(team)" id="numTotalVulns{{ team.name }}">{{ team.totalVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numCriticalVulns{{ team.name }}">{{ team.criticalVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numHighVulns{{ team.name }}">{{ team.highVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numMediumVulns{{ team.name }}">{{ team.mediumVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numLowVulns{{ team.name }}">{{ team.lowVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numInfoVulns{{ team.name }}">{{ team.infoVulnCount }}</td>
            <td ng-click="toggle(team)"></td>
            <td>
                <c:if test="${ underEnterpriseLimit }">
                    <a ng-if="team.showEditButton" id="addApplicationModalButton{{ team.name }}" ng-click="openAppModal(team)" class="btn btn-default">
                        Add Application
                    </a>
                </c:if>
                <c:if test="${ not underEnterpriseLimit }">
                    <a ng-if="team.showEditButton" id="addApplicationModalButton{{ team.name }}" class="btn" ng-click="showAppLimitMessage(<c:out value="${ appLimit }"/>)">
                        Add Application
                    </a>
                </c:if>
            <td>
                <a style="text-decoration:none" id="organizationLink{{ team.name }}" ng-click="goTo(team)">View Team</a>
            </td>
        </tr>

    <tr ng-file-drop-available="dropSupported=true"
        ng-repeat-end class="grey-background" ng-init="teamIndex=team.name">
        <td colspan="8">

                <div collapse="!team.expanded"
                         id="teamInfoDiv{{ team.id }}"
                         class="collapse applicationSection"
                         ng-class="{ expanded: team.expanded }">
                    <div ng-show="team.applications">
                        <div ng-if="team.report" tf-bind-html-unsafe="team.report" class="tableReportDiv" id="teamGraph{{ team.name }}"></div>
                        <div ng-hide="team.report || team.reportFailed || !loading" class="team-report-wrapper">
                            <div style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                        </div>
                        <div ng-show="team.reportFailed" class="team-report-wrapper">
                            Report Failed
                        </div>
                    </div>
                    <div ng-hide="team.applications">
                        No applications were found for this team.
                    </div>

                    <div ng-show='team.applications'>
                        <table id="teamAppTable{{ $index }}">
                            <thead>
                                <tr>
                                    <th style="width:70px;"></th>
                                    <th class="centered fixed-team-header">Total</th>
                                    <th class="centered fixed-team-header">Critical</th>
                                    <th class="centered fixed-team-header">High</th>
                                    <th class="centered fixed-team-header">Medium</th>
                                    <th class="centered fixed-team-header">Low</th>
                                    <th class="centered fixed-team-header">Info</th>
                                    <th style="width:110px;"></th>
                                </tr>
                            </thead>
                            <tr class="app-row" ng-repeat="app in team.applications | filter:active" ng-init="appIndex=$index"
                                    ng-file-drop="onFileSelect(team, app, $files)">
                                <td class="pointer" style="padding:5px;word-wrap: break-word;">
                                    <div style="word-wrap: break-word;width:120px;text-align:left;">
                                        <a id="applicationLink{{ team.name }}-{{ app.name }}" ng-click="goToPage(team, app)">{{ app.name }}</a>
                                    </div>
                                </td>
                                <td class="centered" id="numTotalVulns{{ team.name }}-{{ app.name }}">{{ app.totalVulnCount }}</td>
                                <td class="centered" id="numCriticalVulns{{ team.name }}-{{ app.name }}">{{ app.criticalVulnCount }}</td>
                                <td class="centered" id="numHighVulns{{ team.name }}-{{ app.name }}">{{ app.highVulnCount }}</td>
                                <td class="centered" id="numMediumVulns{{ team.name }}-{{ app.name }}">{{ app.mediumVulnCount }}</td>
                                <td class="centered" id="numLowVulns{{ team.name }}-{{ app.name }}">{{ app.lowVulnCount }}</td>
                                <td class="centered" id="numInfoVulns{{ team.name }}-{{ app.name }}">{{ app.infoVulnCount }}</td>
                                <td class="centered" style="padding:5px;">
                                    <a ng-if="app.showUploadScanButton" id="uploadScanModalLink{{ team.name }}-{{ app.name }}" class="btn"
                                       ng-click="showUploadForm(team, app)">
                                        Upload Scan
                                    </a>
                                </td>
                            </tr>
                        </table>
                    </div>
                </div>

            </div>
        </td>
        <td colspan="3">
            <div ng-show="team.applications"
                 collapse="!team.expanded"
                 class="collapse applicationSection"
                 ng-class="{ expanded: team.expanded }">

                <d3-donut ng-if="team.report" data="team.report" label="reportDiv{{ team.id }}"></d3-donut>

                <div ng-hide="team.report || team.reportFailed || !loading" class="team-report-wrapper">
                    <div style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                </div>
                <div ng-show="team.reportFailed" class="team-report-wrapper">
                    Report Failed
                </div>

            </div>
            </div>
        </td>
    </tr>
    </tbody>
</table>
