
<table ng-show="teams" class="table table-hover white-inner-table">
    <%@ include file="/WEB-INF/views/applications/forms/newApplicationForm.jsp" %>
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

        <spring:url value="/getReport" var="reportUrl"/>

        <tr ng-repeat-start="team in teams" id="teamRow{{ team.id }}" class="pointer" data-target-div="teamInfoDiv{{ team.id }}"
                data-caret-div="caret{{ team.id }}" data-report-div="reportDiv{{ team.id }}"
                ng-init="team.graphUrl='/organizations/' + team.id +'<c:out value='${reportUrl}'/>'">
            <td id="teamCaret{{ team.id }}" ng-click="toggle(team)">
                <span ng-class="{ expanded: team.expanded }" class="caret-right"></span>
            </td>
            <td ng-click="toggle(team)" id="teamName{{ $index }}">
                <div style="word-wrap: break-word;width:300px;text-align:left;">{{ team.name }}</div>
            </td>
            <td class="centered" ng-click="toggle(team)" id="numTotalVulns{{ $index }}">{{ team.vulnCounts[5] }}</td>
            <td class="centered" ng-click="toggle(team)" id="numCriticalVulns{{ $index }}">{{ team.vulnCounts[5] }}</td>
            <td class="centered" ng-click="toggle(team)" id="numHighVulns{{ $index }}">{{ team.vulnCounts[5] }}</td>
            <td class="centered" ng-click="toggle(team)" id="numMediumVulns{{ $index }}">{{ team.vulnCounts[5] }}</td>
            <td class="centered" ng-click="toggle(team)" id="numLowVulns{{ $index }}">{{ team.vulnCounts[5] }}</td>
            <td class="centered" ng-click="toggle(team)" id="numInfoVulns{{ $index }}">{{ team.vulnCounts[5] }}</td>
            <td ng-click="toggle(team)"></td>
            <td>
                <a id="addApplicationModalButton{{ $index }}" ng-click="openAppModal(team)" class="btn btn-default">
                    Add Application
                </a>
            <td>
                <a style="text-decoration:none" id="organizationLink{{ $index }}" href="">View Team</a>
            </td>
        </tr>


        <tr ng-repeat-end class="grey-background">
            <td colspan="11">

                <div collapse="!team.expanded" id="teamInfoDiv{{ team.id }}" class="collapse applicationSection" ng-class="{ expanded: team.expanded }">
                    <div bind-html-unsafe="team.report" class="tableReportDiv" id="reportDiv{{ team.id }}">
                        Loading...
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
                            <tr class="app-row" ng-repeat="app in team.applications | filter:app.active">
                                <td style="padding:5px;word-wrap: break-word;">
                                    <div style="word-wrap: break-word;width:120px;text-align:left;">
                                        <a id="applicationLink{{ $index }}-" href="">
                                            {{ app.name }}
                                        </a>
                                    </div>
                                </td>
                                <td class="centered" id="numTotalVulns{{ $index }}">1</td>
                                <td class="centered" id="numCriticalVulns{{ $index }}">2</td>
                                <td class="centered" id="numHighVulns{{ $index }}">3</td>
                                <td class="centered" id="numMediumVulns{{ $index }}">4</td>
                                <td class="centered" id="numLowVulns{{ $index }}">5</td>
                                <td class="centered" id="numInfoVulns{{ $index }}">6</td>
                                <td class="centered" style="padding:5px;">
                                    <!-- TODO figure out nested indices -->
                                    <a id="uploadScanModalLink{{ $index }}-" href="#uploadScan{{ app.id }}" role="button" class="btn" data-toggle="modal">Upload Scan</a>
                                    <%--<%@ include file="/WEB-INF/views/applications/modals/uploadScanModal.jsp" %>--%>
                                </td>
                            </tr>
                        </table>

                    </div>
                    <div id="myAppModal{{ team.id }}" class="modal hide fade" tabindex="-1"
                         role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
                        <div id="formDiv{{ team.id }}">
                            <%--<%@ include file="/WEB-INF/views/applications/forms/newApplicationForm.jsp" %>--%>
                        </div>
                    </div>
                </div>
            </td>
        </tr>
    </tbody>
</table>
