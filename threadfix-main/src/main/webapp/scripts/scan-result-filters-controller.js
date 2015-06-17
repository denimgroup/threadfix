var module = angular.module('threadfix');

module.controller('ScanResultFiltersController', function($scope, $http, $modal, $log, tfEncoder, threadFixModalService){

    $scope.scanResultFilters = [];

    var compare = function(a, b){
        var scannerCompare = a.scannerTypeName.localeCompare(b.scannerTypeName);
        if(scannerCompare !=0){
            return scannerCompare;
        }

        if(a.genericSeverity.intValue == b.genericSeverity.intValue){
            return 0;
        }
        if(a.genericSeverity.intValue > b.genericSeverity.intValue){
            return -1;
        }
        if(a.genericSeverity.intValue < b.genericSeverity.intValue){
            return 1;
        }
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/scanResultFilters/info')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.scanResultFilters = data.object.scanResultFilters;
                    $scope.channelTypes = data.object.channelTypes;
                    $scope.severities = data.object.severities;

                    if ($scope.scanResultFilters.length === 0) {
                        $scope.scanResultFilters = undefined;
                    } else {
                        $scope.scanResultFilters.sort(compare);
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newScanResultFilterModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/scanResultFilters/new");
                },
                object: function() {
                    return {};
                },
                config: function() {
                    return {
                        channelTypes: $scope.channelTypes,
                        severities: $scope.severities
                    };
                },
                buttonText: function() {
                    return "Create Filter";
                }
            }
        });

        modalInstance.result.then(function (newFilter) {

            if (!$scope.scanResultFilters) {
                $scope.scanResultFilters = [];
            }

            $scope.scanResultFilters.push(newFilter);

            $scope.scanResultFilters.sort(compare);

            $scope.successMessage = "Successfully created filter ";

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openEditModal = function(filter) {
        var modalInstance = $modal.open({
            templateUrl: 'editScanResultFilterModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/scanResultFilters/" + filter.id + "/edit");
                },
                object: function() {
                    var filterCopy = angular.copy(filter);
                    return filter;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                config: function() {
                    return {
                        channelTypes: $scope.channelTypes,
                        severities: $scope.severities
                    };
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/scanResultFilters/" + filter.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedFilter) {

            if (editedFilter) {
                threadFixModalService.deleteElement($scope.scanResultFilters, filter);
                threadFixModalService.addElement($scope.scanResultFilters, editedFilter);

                $scope.successMessage = "Successfully edited filter.";
                $scope.scanResultFilters.sort(compare);
            } else {

                threadFixModalService.deleteElement($scope.scanResultFilters, filter);
                $scope.empty = $scope.scanResultFilters.length === 0 || $scope.scanResultFilters == undefined;
                $scope.successMessage = "Scan result filter was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }
});