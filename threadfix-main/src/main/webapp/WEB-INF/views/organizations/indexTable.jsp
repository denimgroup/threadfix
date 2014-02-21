
<div style="padding-bottom:10px">
    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
        <a id="addTeamModalButton" ng-click="openTeamModal()" class="btn">Add Team</a>
    </security:authorize>
    <a ng-show="teams" class="btn" id="expandAllButton" ng-click="expand()">Expand All</a>
    <a ng-show="teams" class="btn" id="collapseAllButton" ng-click="contract()">Collapse All</a>
</div>

<table ng-show="teams" class="table table-hover white-inner-table">
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
            <td id="teamCaret{{ team.id }}" ng-click="toggle(team)">
                <span ng-class="{ expanded: team.expanded }" class="caret-right"></span>
            </td>
            <td ng-click="toggle(team)" id="teamName{{ $index }}">
                <div style="word-wrap: break-word;width:300px;text-align:left;">{{ team.name }}</div>
            </td>
            <td class="centered" ng-click="toggle(team)" id="numTotalVulns{{ $index }}">{{ team.totalVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numCriticalVulns{{ $index }}">{{ team.criticalVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numHighVulns{{ $index }}">{{ team.highVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numMediumVulns{{ $index }}">{{ team.mediumVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numLowVulns{{ $index }}">{{ team.lowVulnCount }}</td>
            <td class="centered" ng-click="toggle(team)" id="numInfoVulns{{ $index }}">{{ team.infoVulnCount }}</td>
            <td ng-click="toggle(team)"></td>
            <td>
                <a id="addApplicationModalButton{{ $index }}" ng-click="openAppModal(team)" class="btn btn-default">
                    Add Application
                </a>
            <td>
                <a style="text-decoration:none" id="organizationLink{{ $index }}" href="/organizations/{{ team.id }}{{ csrfToken }}">View Team</a>
            </td>
        </tr>


        <tr ng-file-drop-available="dropSupported=true"
            ng-repeat-end class="grey-background" ng-init="teamIndex=$index">
            <td colspan="11">

                <div collapse="!team.expanded"
                         id="teamInfoDiv{{ team.id }}"
                         class="collapse applicationSection"
                         ng-class="{ expanded: team.expanded }">
                    <div ng-show="team.report" bind-html-unsafe="team.report" class="tableReportDiv" id="reportDiv{{ team.id }}"></div>
                    <div ng-hide="team.report" ng-hide="team.reportFailed" class="team-report-wrapper">
                        <div style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                    </div>
                    <div ng-show="team.reportFailed" class="team-report-wrapper">
                        Report Failed
                    </div>

                    <div ng-hide="team.applications">
                        No applications were found for this team.
                    </div>

                    <div ng-show='team.applications' id="teamAppTableDiv{{ $index }}">
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
                            <tr class="app-row" ng-repeat="app in team.applications | filter:app.active" ng-init="appIndex=$index"
                                    ng-file-drop="onFileSelect(team, app, $files)">
                                <td style="padding:5px;word-wrap: break-word;">
                                    <div style="word-wrap: break-word;width:120px;text-align:left;">
                                        <a id="applicationLink{{ teamIndex }}-{{ appIndex}}"
                                           href="/organizations/{{ team.id }}/applications/{{ app.id }}{{ csrfToken }}">
                                            {{ app.name }}
                                        </a>
                                    </div>
                                </td>
                                <td class="centered" id="numTotalVulns{{ teamIndex }}-{{ appIndex}}">{{ app.totalVulnCount }}</td>
                                <td class="centered" id="numCriticalVulns{{ teamIndex }}-{{ appIndex}}">{{ app.criticalVulnCount }}</td>
                                <td class="centered" id="numHighVulns{{ teamIndex }}-{{ appIndex}}">{{ app.highVulnCount }}</td>
                                <td class="centered" id="numMediumVulns{{ teamIndex }}-{{ appIndex}}">{{ app.mediumVulnCount }}</td>
                                <td class="centered" id="numLowVulns{{ teamIndex }}-{{ appIndex}}">{{ app.lowVulnCount }}</td>
                                <td class="centered" id="numInfoVulns{{ teamIndex }}-{{ appIndex}}">{{ app.infoVulnCount }}</td>
                                <td class="centered" style="padding:5px;">
                                    <a id="uploadScanModalLink{{ teamIndex }}-{{ appIndex}}" class="btn"
                                            ng-click="showUploadForm(team, app)">
                                        Upload Scan
                                    </a>
                                </td>
                            </tr>
                        </table>

                    </div>
                </div>
            </td>
        </tr>
    </tbody>
</table>
