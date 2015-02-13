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
                        }">{{ vuln.genericSeverity.name }}</td>
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

        <%--<tr ng-repeat-end class="grey-background" id="comments{{ $index }}" ng-if='vuln.vulnerabilityComments'>--%>
        <%--<td >--%>
        <%--&lt;%&ndash;<div collapse="!vuln.expanded"&ndash;%&gt;--%>
        <%--&lt;%&ndash;id="vulnInfoDiv{{ $index }}"&ndash;%&gt;--%>
        <%--&lt;%&ndash;class="collapse vulnerabilitySection"&ndash;%&gt;--%>
        <%--&lt;%&ndash;ng-class="{ expanded: vuln.expanded }">&ndash;%&gt;--%>

        <%--&lt;%&ndash;<div ng-if='vuln.vulnerabilityComments'>&ndash;%&gt;--%>
        <%--<table id="vulnCommentTable{{ $index }}">--%>
        <%--<thead>--%>
        <%--<tr>--%>
        <%--<th>User</th>--%>
        <%--<th>Date</th>--%>
        <%--<th>Comment</th>--%>
        <%--<th>Tag</th>--%>
        <%--<tr>--%>
        <%--</thead>--%>
        <%--<tbody>--%>
        <%--<tr ng-repeat="comment in vuln.vulnerabilityComments" class="bodyRow left-align">--%>
        <%--<td id="commentUser{{ $index }}">{{ comment.username }}</td>--%>
        <%--<td id="commentDate{{ $index }}">{{ comment.time | date:'yyyy-MM-dd HH:mm' }}</td>--%>
        <%--<td id="commentText{{ $index }}">--%>
        <%--<div class="vuln-comment-word-wrap">--%>
        <%--{{ comment.comment }}--%>
        <%--</div>--%>
        <%--</td>--%>
        <%--<td class="left-align" >--%>
        <%--<span ng-repeat="cmtTag in comment.tags">--%>
        <%--<a class="pointer" id="cmtTag{{ $index }}" ng-click="goToTag(cmtTag)">{{cmtTag.name}}<span ng-hide="$index===comment.tags.length-1">,</span></a>--%>
        <%--</span>--%>
        <%--</td>--%>
        <%--</tr>--%>
        <%--</tbody>--%>
        <%--</table>--%>
        <%--&lt;%&ndash;</div>&ndash;%&gt;--%>
        <%--&lt;%&ndash;</div>&ndash;%&gt;--%>
        <%--</td>--%>
        <%--<td></td>--%>
        <%--<td></td>--%>
        <%--<td></td>--%>
        <%--</tr>--%>
        </tbody>
    </table>
</div>