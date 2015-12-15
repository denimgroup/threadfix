<div id="sharedComponents" ng-if="sharedVulns">
    <h4>Also Found In</h4>
    <table class="table sortable table-hover" id="sharedComponentTable">
        <thead>
        <tr>
            <th style="width:5px; padding:0"></th>
            <th>Application</th>
            <th>Team</th>
            <th></th>
        </tr>
        </thead>
        <tbody>
        <tr ng-repeat="vuln in sharedVulns" class="finding-row">
            <td class="{{ badgeClassMap[vuln.genericSeverity.intValue] }}" style="padding:0"></td>
            <td class="word-wrap" id="appName{{ $index }}"><a ng-href="{{vuln.appUrl}}">{{ vuln.app.name }}</a></td>
            <td class="word-wrap" id="teamName{{ $index }}"><a ng-href="{{vuln.teamUrl}}">{{ vuln.team.name }}</a></td>
            <td><a ng-href="{{vuln.vulnUrl}}">View Vulnerability</a></td>
        </tr>
        </tbody>
    </table>
</div>