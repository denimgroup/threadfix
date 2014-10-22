<table class="table">
	<thead>
		<tr>
			<th>User</th>
			<th>Date</th>
			<th>Comment</th>
            <th>Tag</th>
            <th ng-if="<c:out value='${canModifyVulnerabilities}'/> && canUpdateVulnComment" class="last"></th>
		<tr>
	</thead>
	<tbody>
        <tr ng-hide="vulnerability.vulnerabilityComments" class="bodyRow">
            <td colspan="4" style="text-align:center;">No comments found.</td>
        </tr>
        <tr ng-show="vulnerability.vulnerabilityComments" ng-repeat="comment in vulnerability.vulnerabilityComments" class="bodyRow left-align">
            <td id="commentUser{{ $index }}">{{ comment.username }}</td>
            <td id="commentDate{{ $index }}">{{ comment.time | date:'yyyy-MM-dd HH:mm' }}</td>
            <td id="commentText{{ $index }}">
                <div class="vuln-comment-word-wrap">
                    {{ comment.comment }}
                </div>
            </td>
            <td class="left-align" >
                <multi-select
                        input-model="comment.tagsList"
                        output-model="comment.tags"
                        button-label="name"
                        item-label="name"
                        tick-property="selected"
                        on-item-click="changeComment(vulnerability, comment)"
                        max-labels="1"
                        >
                </multi-select>
            </td>
            <td ng-if="<c:out value='${canModifyVulnerabilities}'/> && canUpdateVulnComment">
                <a class="btn btn-primary"
                   ng-class="{ disabled : !comment.commentChanged }"
                   ng-click="updateVulnComment(vulnerability, comment)"
                   >Update</a>
            </td>
        </tr>
	</tbody>
</table>

