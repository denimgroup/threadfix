var myAppModule = angular.module('threadfix')

myAppModule.controller('TeamDetailPageController', function ($scope, $window, $http, $modal, $log, $rootScope, tfEncoder) {

    $scope.rightReportTitle = "Top 10 Vulnerable Applications";
    $scope.empty = false;

    $scope.onFileSelect = function($files) {
        $scope.$broadcast('fileDragged', $files);
    };

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.teamId  = $window.location.pathname.match(/([0-9]+)$/)[0];

    $scope.showAppLimitMessage = function(number) {
        alert('You have reached the application limit of ' + number + ' for your current license. To upgrade your license, please contact Denim Group.');
    }

    $scope.$on('rootScopeInitialized', function() {
        $scope.reportQuery = "&orgId=" + $scope.teamId;
        $http.get(tfEncoder.encodeRelative($scope.teamId + "/info")).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.team = data.object.team;
                    $scope.$broadcast('seeMoreExtension', "/" + $scope.team.id);
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
                    return tfEncoder.encode("/organizations/" + $scope.team.id + "/edit");
                },
                object: function () {
                    return $scope.team;
                },
                buttonText: function() {
                    return "Save Changes";
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/organizations/" + $scope.team.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedTeam) {
            if (editedTeam) {
            $scope.successMessage = "Successfully edited team";
            } else {
                $window.location.href = tfEncoder.encode("/organizations");
            }
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
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/organizations/" + $scope.team.id + "/modalAddApp");
                },
                object: function () {
                    return application;
                },
                config: function() {
                    return {};
                },
                buttonText: function() {
                    return "Add Application";
                }
            }
        });

        modalInstance.result.then(function (newApplication) {

            if (!$scope.applications || $scope.applications.length === 0) {
                $scope.applications = [];
            }
            $scope.applications.push(newApplication);

            $scope.applications.sort(nameCompare);

            $scope.successMessage = "Successfully added application " + newApplication.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.goToPage = function(app) {
        $window.location.href = tfEncoder.encodeRelative($scope.team.id + "/applications/" + app.id);
    }

});