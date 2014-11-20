var module = angular.module('threadfix');

module.controller('GRCToolsController', function($scope, $http, $modal, $rootScope, $log, tfEncoder, threadFixModalService) {

    $scope.grcTools = [];

    $scope.loading = true;

    $scope.empty = true;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/grctools/info')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.grcTools = data.object.grcTools;

                    $scope.grcToolTypes = data.object.grcToolTypes;

                    $scope.grcApplications = data.object.grcApplications;

                    $scope.empty = $scope.grcTools.length === 0;

                    $scope.grcTools.sort(nameCompare);

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newGRCToolModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/grctools/new");
                },
                object: function() {
                    return {
                        grcToolsType: $scope.grcToolTypes[0]
                    };
                },
                config: function() {
                    return {
                        toolTypes: $scope.grcToolTypes
                    };
                },
                buttonText: function() {
                    return "Create GRC Tool";
                }
            }
        });

        modalInstance.result.then(function (newGRCTool) {

            $scope.grcTools.push(newGRCTool);

            $scope.empty = $scope.grcTools.length === 0;

            $scope.grcTools.sort(nameCompare);

            $scope.successMessage = "Successfully created GRC Tool " + newGRCTool.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.updateGRCApps = function(grcTool) {
        $http.get(tfEncoder.encode('/configuration/grctools/' + grcTool.id + '/getApps')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.grcApplications = data.object;

                    if ($scope.grcApplications.length === 0) {
                        $scope.grcApplications = undefined;
                    } else {
                        $scope.grcApplications.sort(nameCompare);
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve GRC Applications. HTTP status was " + status;
            });
    };

    $scope.paginate = function() {
        if ($scope.grcApplications) {
            if (!provider.page) {
                provider.page = 1;
            }

            var targetPage = provider.page - 1;

            if ($scope.grcApplications.length > (provider.page * 100)) {
                provider.displayApps = $scope.grcApplications.slice(targetPage * 100, 100 * provider.page)
            } else {
                provider.displayApps = $scope.grcApplications.slice(targetPage * 100)
            }
        }
    };

    $scope.goToTeam = function(team) {
        window.location.href = tfEncoder.encode("/organizations/" + team.id);
    };

});