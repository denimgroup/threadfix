<div ng-controller="ActivityFeedController">
    <span ng-repeat="activity in feed.activityList">
        {{ activity.date | date }} | {{ activity.user.name }} | {{ activity.details }} <a ng-href="{{ encode(activity.linkPath) }}">{{ activity.linkText }}</a>
        <hr>
    </span>
</div>