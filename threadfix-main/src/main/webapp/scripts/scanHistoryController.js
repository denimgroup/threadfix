var myAppModule = angular.module('threadfix')

myAppModule.controller('ScanHistoryController', function($scope, $log, $http, $window) {

    $scope.initialized = false;

    $scope.pageNumber = 1;
    $scope.numScans = 0;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    var setDate = function(scan) {
        var time = new Date(scan.importTime)
        scan.importTime = (time.getMonth() + "/" + time.getDate() + "/" + time.getFullYear() + " " + time.getHours() + ":" + time.getMinutes());
    }

    // since we need the csrfToken to make the request, we need to wait until it's initialized
    $scope.$watch('csrfToken', function() {
        $http.post("/scans/table/" + $scope.pageNumber + $scope.csrfToken).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                if (data.success) {
                    $scope.scans = data.object.scanList;
                    $scope.numScans = data.object.numScans;
                    //$scope.teams.sort(nameCompare)

                    $scope.scans.forEach(setDate);

                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.goTo = function(scan) {
        $window.location.href = "/organizations/" + scan.team.id + "/applications/" + scan.app.id + "/scans/" + scan.id + $scope.csrfToken;
    };

});
