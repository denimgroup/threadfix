var myAppModule = angular.module('threadfix');

myAppModule.controller('CommunitySeverityTextController', function ($scope, $http, $log, tfEncoder, customSeverityService) {

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                    Initial Load
    //////////////////////////////////////////////////////////////////////////////////////////

    var refresh = function() {
        $http.get(tfEncoder.encode('/severities/list')).
            success(function (data) {

                if (data.success) {
                    $scope.severities = data.object.genericSeverities;
                    customSeverityService.setSeverities($scope.severities);

                    $scope.severities.forEach(function(severity) {
                        severity.backup = severity.customName;
                    });

                    $scope.severityFilter = data.object.globalSeverityFilter;

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function (data, status) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve group list. HTTP status was " + status;
            });
    };

    $scope.$on('rootScopeInitialized', function() {
        refresh();
    });

    $scope.setSeverity = function(severity, value) {
        if ($scope.severityFilter.enabled) {
            $scope.severityFilter[severity] = value;
        }
    };

    $scope.submitSeverityFilterForm = function() {
        $scope.submittingSeverityFilter = true;

        $scope.severitySuccessMessage = undefined;
        $scope.severityErrorMessage = undefined;

        $http.post(tfEncoder.encode('/configuration/filters/severityFilter/set'), $scope.severityFilter).
            success(function(data, status, headers, config) {

                if (data.success) {
                    if ($scope.type === 'Global') {
                        $scope.severitySuccessMessage = "Successfully saved filter settings. " +
                        "ThreadFix is updating all vulnerabilities in the background. It may take a few minutes to finish.";
                    } else
                        $scope.severitySuccessMessage = "Successfully saved filter settings.";
                } else {
                    $scope.severityErrorMessage = "Failure. Message was : " + data.message;
                }

                $scope.submittingSeverityFilter = false;
            }).
            error(function(data, status, headers, config) {
                $scope.submittingSeverityFilter = false;
                $scope.severityErrorMessage = "Failed to retrieve map. HTTP status was " + status;
            });
    };

});
