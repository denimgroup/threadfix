<div ng-controller="ActivityFeedController">
    <table class="table">
        <tr ng-repeat="activity in feed.activityList">
            <td>{{ activity.date | date }}</td>
            <td>{{ activity.beforeLink }}<a ng-href="{{ encode(activity.linkPath) }}">{{ activity.linkText }}</a>{{activity.afterLink}}</td>
        </tr>
    </table>
</div>