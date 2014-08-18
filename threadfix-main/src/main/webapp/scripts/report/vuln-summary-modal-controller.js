var myAppModule = angular.module('threadfix')

myAppModule.controller('VulnSummaryModalController', function ($scope, $window, $rootScope, $modalInstance, $modal, $http, tfEncoder, threadFixModalService, scope, isStay, vulnSearchParameterService) {

    $scope.header = "Vulnerabilities Summary";
    $scope.loading = true;
    var severities = ['Info','Low', 'Medium', 'High', 'Critical'];

    var url;
//    if (scope.treeApplication) {
//        url = "/organizations/" + scope.treeTeam.id + "/applications/" + scope.treeApplication.id;
//    } else if (scope.treeTeam) {
//        url = "/organizations/" + scope.treeTeam.id;
//    } else
        url = "/reports";

    if (scope.treeApplication || (scope.parameters.applications && scope.parameters.applications.length > 0)) {
        scope.treeTeam = undefined;
        scope.parameters.teams = [];
        scope.teams = [];
    }
    scope.searchApplications = angular.copy(scope.parameters.applications);
    scope.teams = angular.copy(scope.parameters.teams);

    vulnSearchParameterService.updateParameters(scope, scope.parameters);

    $http.post(tfEncoder.encode("/reports/tree"), scope.parameters).
        success(function(data, status, headers, config) {
            $scope.loading = false;
            $scope.categories = data.object;
            if ($scope.categories) {
                $scope.categories.forEach(function(category){
                    category.severityStr = severities[category.intValue-1];
                });
            }
        }).
        error(function(data, status, headers, config) {
            $scope.loading = false;
            console.log("Got " + status + " back.");
        });

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };

    $scope.goToDetail = function () {
        $http.post(tfEncoder.encode("/reports/saveParameters"), scope.parameters).
            success(function() {
                if (isStay) {
                    $modalInstance.dismiss('cancel');
                    $rootScope.$broadcast('loadVulnerabilitySearchTable');
                } else {
                    $window.location.href = tfEncoder.encode(url);
                }
            }).
            error(function(data, status, headers, config) {
                $scope.error = "Failure. HTTP status was " + status;
            });
    };

});
