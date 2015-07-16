<div>

    <div ng-if="!vulnList">
        No Vulnerabilities Found.
    </div>

    <table ng-if="vulnList" class="table table-hover white-inner-table">
        <thead>
        <tr>
            <th style="width:200px;">Vulnerability Name</th>
            <th style="text-align:left;">Severity</th>
            <th style="text-align:left;">Application</th>
            <th style="text-align:left;">Team</th>
            <th style="text-align:left; width:100px;">Comment</th>
        </tr>
        </thead>
        <tbody>

        <tr ng-repeat="vuln in vulnList" id="vulnRow{{ $index }}" class="pointer">
            <td ng-click="toggle(vuln)" id="vulnName{{ $index }}" style="word-wrap: break-word;text-align:left;">
                {{ vuln.genericVulnerability.name }}
            </td>
            <td ng-click="toggle(vuln)" class="centered" id="severity{{ $index }}"
                ng-class="{
                        'badge-critical': vuln.genericSeverity.intValue === 5,
                        'badge-high': vuln.genericSeverity.intValue === 4,
                        'badge-medium': vuln.genericSeverity.intValue === 3,
                        'badge-low': vuln.genericSeverity.intValue === 2,
                        'badge-info': vuln.genericSeverity.intValue === 1
                        }">{{ vuln.genericSeverity.displayName }}</td>
            <td style="word-wrap: break-word;" class="centered" id="appName{{ $index }}"><a ng-click="goToAppFromVuln(vuln)">{{ vuln.app.name }}</a></td>
            <td style="word-wrap: break-word;" class="centered" id="teamName{{ $index }}"><a ng-click="goToTeamFromVuln(vuln)">{{ vuln.team.name }}</a></td>
            <td style="word-wrap: break-word;" class="centered" id="comment{{ $index }}">
                <div ng-repeat="comment in vuln.vulnerabilityComments">
                    <b>User </b> {{ comment.username }}
                    <b>Date </b> {{ comment.time | date:'yyyy-MM-dd HH:mm' }}
                    <b>Comment </b> {{ comment.comment }}
                    <b>Tag </b> <a ng-repeat="cmtTag in comment.tags" class="pointer" id="cmtTag{{ $index }}" ng-click="goToTag(cmtTag)">{{cmtTag.name}}<a ng-if="$index===comment.tags.length-1">,</a></a>
                    <br>
                </div>
            </td>
        </tr>
        </tbody>
    </table>
</div>