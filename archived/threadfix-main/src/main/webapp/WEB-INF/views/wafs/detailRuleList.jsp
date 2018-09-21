
    <div ng-show="waf.wafRules">
    <h3>WAF Rule Statistics <a ng-click="showRuleInfo = !showRuleInfo" class="pointer">View Details</a></h3>
        <div id="statisticsDiv" ng-show="showRuleInfo">
            <a class="pointer" ng-repeat="wafRule in waf.wafRules" ng-click="goToRule(wafRule)"> {{ wafRule.nativeId }} - fired {{wafRule.securityEventsCount}} times<br></a>
            <br/>
        </div>
    </div>
    <div ng-show="rulesText">
        <h3>WAF Rules:</h3>

        <div class="centered">
            <a target="_blank" class="btn" type="submit" ng-href="{{ base }}/rules/download/app/{{ wafApplicationId }}{{ csrfToken }}">Download Waf Rules</a>
        </div>
        <br/>
        <div id="wafrule">
            <pre>{{ rulesText }}</pre>
        </div>
    </div>
