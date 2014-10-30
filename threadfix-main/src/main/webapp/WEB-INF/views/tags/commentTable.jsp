<div>
    <h4 style="padding-top:10px">Tagged Vulnerability Comments</h4>
    <%--<div ng-form="mappedForm" class="pagination" ng-show="numApps > 100">--%>
    <%--<pagination class="no-margin" total-items="numApps / 10" max-size="5" page="page"></pagination>--%>

    <%--<input name="pageMappedInput"  ng-enter="goToPage(mappedForm.$valid)" style="width:50px" type="number" ng-model="pageInput" max="{{numberOfMappedPages * 1}}" min="1"/>--%>
    <%--<button class="btn" ng-class="{ disabled : mappedForm.$invalid }" ng-click="goToPage(mappedForm.$valid)"> Go to Page </button>--%>
    <%--<span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.min || mappedForm.pageMappedInput.$error.max">Input number from 1 to {{numberOfMappedPages}}</span>--%>
    <%--<span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.number">Not a valid number</span>--%>
    <%--</div>--%>
    <div ng-show="loading" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <div style="padding-bottom:10px">
        <a ng-show="vulnList" class="btn" id="expandAllButton" ng-click="expand()">Expand All</a>
        <a ng-show="vulnList" class="btn" id="collapseAllButton" ng-click="contract()">Collapse All</a>
    </div>

    <table ng-show="vulnList" class="table table-hover white-inner-table">
        <thead>
        <tr>
            <th style="width:8px"></th>
            <th>Vulnerability Name</th>
            <th class="centered fixed-team-header">Application</th>
            <th class="centered fixed-team-header">Team</th>
            <th style="width:70px;"></th>
        </tr>
        </thead>
        <tbody>
        <tr ng-repeat-start="vuln in vulnList" id="vulnRow{{ vuln.vulnId }}" class="pointer">
            <td id="vulnCaret{{ vuln.vulnId }}" ng-click="toggle(vuln)">
                <span ng-class="{ expanded: vuln.expanded }" class="caret-right"></span>
            </td>
            <td ng-click="toggle(vuln)" id="vulnName{{ vuln.vulnId }}" style="word-wrap: break-word;text-align:left;">{{ vuln.vulnName }}
            </td>
            <td class="centered" id="appName{{ vuln.appId }}"><a ng-click="goToAppFromVuln(vuln)">{{ vuln.appName }}</a></td>
            <td class="centered" id="teamName{{ vuln.teamId }}"><a ng-click="goToTeamFromVuln(vuln)">{{ vuln.teamName }}</a></td>
            <td>
                <a style="text-decoration:none" id="vulnLink{{ vuln.vulnId }}" ng-click="goToVuln(vuln)">View More</a>
            </td>
        </tr>

        <tr ng-repeat-end class="grey-background">
            <td colspan="5">

                <div collapse="!vuln.expanded"
                     id="vulnInfoDiv{{ vuln.vulnId }}"
                     class="collapse vulnerabilitySection"
                     ng-class="{ expanded: vuln.expanded }">

                    <div ng-show='vuln.comments'>
                        <table id="vulnCommentTable{{ $index }}">
                            <thead>
                            <tr>
                                <th>User</th>
                                <th>Date</th>
                                <th>Comment</th>
                                <th>Tag</th>
                            <tr>
                            </thead>
                            <tbody>
                            <tr ng-repeat="comment in vuln.comments" class="bodyRow left-align">
                                <td id="commentUser{{ $index }}">{{ comment.username }}</td>
                                <td id="commentDate{{ $index }}">{{ comment.time | date:'yyyy-MM-dd HH:mm' }}</td>
                                <td id="commentText{{ $index }}">
                                    <div class="vuln-comment-word-wrap">
                                        {{ comment.comment }}
                                    </div>
                                </td>
                                <td class="left-align" >
                        <span ng-repeat="cmtTag in comment.tags">
                            <a class="pointer" id="cmtTag{{ $index }}" ng-click="goToTag(cmtTag)">{{cmtTag.name}}<span ng-hide="$index===comment.tags.length-1">,</span></a>
                        </span>
                                </td>
                            </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </td>
        </tr>
        </tbody>
    </table>
</div>