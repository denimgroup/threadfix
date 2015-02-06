var module = angular.module('threadfix')

module.controller('WafsPageController', function($scope, $http, $modal, $log, tfEncoder){

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/wafs/map')).
            success(function(data, status, headers, config) {

                if (data.success) {

                    if (data.object.wafs.length > 0) {
                        $scope.wafs = data.object.wafs;
                        $scope.wafs.sort(nameCompare);
                    }

                    $scope.wafTypes = data.object.wafTypes;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {

        var modalInstance = $modal.open({
            templateUrl: 'createWafModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/wafs/new/ajax/appPage");
                },
                object: function () {
                    return {
                        wafType: {
                            id: 1
                        }
                    };
                },
                config: function() {
                    return {
                        wafTypeList: $scope.wafTypes
                    }
                },
                buttonText: function() {
                    return "Create WAF";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (waf) {
            if (!$scope.wafs) {
                $scope.wafs = [ waf ];
            } else {
                $scope.wafs.push(waf);

                $scope.wafs.sort(nameCompare);
            }

            $scope.successMessage = "Successfully created waf " + waf.name;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openEditModal = function(waf) {
        var modalInstance = $modal.open({
            templateUrl: 'editWafModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/wafs/" + waf.id + "/edit");
                },
                object: function() {
                    return {
                        name: waf.name,
                        wafType: waf.wafType
                    };
                },
                buttonText: function() {
                    return "Save Edits";
                },
                config: function() {
                    return {
                        wafTypeList: $scope.wafTypes
                    }
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/wafs/" + waf.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (wafs) {

            if (wafs) {
                $scope.wafs = wafs;
                $scope.wafs.sort(nameCompare);
                $scope.errorMessage = "";
                $scope.successMessage = "Successfully edited waf " + waf.name;
            } else {
                if (waf.canDelete) {
                    var index = $scope.wafs.indexOf(waf);
                    if (index > -1) {
                        $scope.wafs.splice(index, 1);
                    }
                    if ($scope.wafs.length === 0) {
                        $scope.wafs = undefined;
                    }
                    $scope.successMessage = "The WAF deletion was successful for WAF " + waf.name;
                    $scope.errorMessage = "";
                } else {
                    $scope.successMessage = "";
                    $scope.errorMessage = "Failed to delete a WAF with application mappings.";
                }
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.goToWaf = function(waf) {
        window.location.href = tfEncoder.encode("/wafs/" + waf.id);
    }

});