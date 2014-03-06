var module = angular.module('threadfix')

module.controller('WafsPageController', function($scope, $http, $modal, $log){

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$watch('csrfToken', function() {
        $http.get('/wafs/map' + $scope.csrfToken).
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
                    return "/wafs/new/ajax/appPage" + $scope.csrfToken;
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
    }

    $scope.openEditModal = function(waf) {
        var modalInstance = $modal.open({
            templateUrl: 'editWafModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return "/wafs/" + waf.id + "/edit" + $scope.csrfToken;
                },
                object: function() {
                    return waf;
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
                    return "/wafs/" + waf.id + "/delete" + $scope.csrfToken;
                }
            }
        });

        modalInstance.result.then(function (editedWaf) {
            var index = $scope.wafs.indexOf(waf);

            if (index > -1) {
                $scope.wafs.splice(index, 1);
            }

            if (editedWaf) {
                $scope.wafs.push(editedWaf);

                $scope.wafs.sort(nameCompare);
            }

            if ($scope.wafs.length === 0){
                $scope.wafs = undefined;
            }

            $scope.successMessage = "Successfully edited waf " + editedWaf.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.goToWaf = function(waf) {
        window.location.href = "/wafs/" + waf.id + $scope.csrfToken;
    }

});