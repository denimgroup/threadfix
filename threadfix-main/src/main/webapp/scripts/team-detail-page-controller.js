var myAppModule = angular.module('threadfix')

myAppModule.controller('TeamDetailPageController', function ($scope, $window, $http, $modal, $log) {

    $scope.rightReportTitle = "Top 10 Vulnerable Applications";
    $scope.empty = false;

    $scope.onFileSelect = function($files) {
        $scope.$broadcast('fileDragged', $files);
    };

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.teamId  = $window.location.pathname.match(/([0-9]+)$/)[0];

    $scope.$watch('csrfToken', function() {
        $scope.reportQuery = $scope.csrfToken + "&orgId=" + $scope.teamId;
        $http.get($scope.teamId + "/info" + $scope.csrfToken).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.team = data.object.team;
                    $scope.applications = data.object.applications;
                } else {
                    var error = "Error encountered. Message was " + $scope.message;
                    $scope.errorMessage = error;
                    $log.error(error);
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Encountered error. HTTP status was " + status;
                $log.error("Encountered error. HTTP status was " + status);
            });
    });

    $scope.openEditModal = function() {

        var modalInstance = $modal.open({
            templateUrl: 'editTeamModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return "/organizations/" + $scope.team.id + "/edit" + $scope.csrfToken;
                },
                object: function () {
                    return $scope.team;
                },
                buttonText: function() {
                    return "Save Changes";
                }
            }
        });

        modalInstance.result.then(function (newApplication) {

            $scope.applications.push(newApplication);

            $scope.applications.sort(nameCompare);

            $scope.successMessage = "Successfully added application " + newApplication.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openAppModal = function() {

        var application = {
            team: {
                id: $scope.team.id,
                name: $scope.team.name
            },
            applicationCriticality: {
                id: 2
            },
            frameworkType: 'Detect'
        };

        var modalInstance = $modal.open({
            templateUrl: 'newApplicationModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return "/organizations/" + $scope.team.id + "/modalAddApp" + $scope.csrfToken;
                },
                object: function () {
                    return application;
                },
                buttonText: function() {
                    return "Add Application";
                }
            }
        });

        modalInstance.result.then(function (newApplication) {

            $scope.applications.push(newApplication);

            $scope.applications.sort(nameCompare);

            $scope.successMessage = "Successfully added application " + newApplication.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.goToPage = function(app) {
        $window.location.href = $scope.team.id + "/applications/" + app.id + $scope.csrfToken;
    }

});