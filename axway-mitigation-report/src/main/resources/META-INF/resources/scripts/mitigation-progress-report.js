var myAppModule = angular.module('threadfix');

myAppModule.controller('MitigationProgressReport', function ($scope, $window, $modal, $http, $log, $rootScope,
                                                             tfEncoder, mitigationUtils) {

    $scope.scans = {};
    $scope.parameters = {
        teams: [],
        applications: [],
        scanners: [],
        genericVulnerabilities: [],
        severities: {},
        numberVulnerabilities: 100000,
        showOpen: false,
        showClosed: true,
        showFalsePositive: false,
        showHidden: false
    };


    $scope.scan = {};
    $scope.activeScanners = {};

    $scope.isNotNull = function(elem){
        return !elem.isNull;
    };

    $scope.$on('rootScopeInitialized', function(){
        getData();
        getConfig();
        // TODO for Fortify SSC getRemote();
    });

    $scope.$on('vulnChanged', function(){
        $scope.activeResults.clear();
        getData();
        getConfig();
    });

    var getChannels = function() {
        $http.post(tfEncoder.encode("/graphConfig/channels")).
            success(function (data, status, headers, config) {
                getConfig();
            })
    };

    $scope.activeResults = [];

    var getConfig = function() {
        $http.post(tfEncoder.encode("/graphConfig/data")).
            success(function (data, status, headers, config) {
                if(data.object.scanners.length == 0){
                    getChannels();
                } else {
                    $scope.config = data.object.scanners;
                }
            })
    };

    // TODO for Fortify SSC
    var getRemote = function(){
        $http.post(tfEncoder.encode("/graphConfig/remote/" + $scope.$parent.appId)).
            success(function(data, status, headers, config){
                $scope.remoteScan = data.object.remote;

                mitigationUtils.refreshRemoteVulns($scope);
            })
    };

    var getData = function(){
        var parameters = angular.copy($scope.parameters);
        $http.post(tfEncoder.encode("/graphConfig/table"), parameters).
            success(function(data, status, headers, config) {
                $scope.open = data.object.open;
                $scope.closed = data.object.closed;

                mitigationUtils.refreshVulns($scope);
            });
    };

    $scope.viewScan = function(id) {
        window.location.href = tfEncoder.encode("/organizations/" + $scope.$parent.teamId +
                                    "/applications/" + $scope.$parent.appId + '/scans/' + id);
    };

    $scope.showEditModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'graphConfig.html',
            controller: 'GraphConfigModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/graphConfig");
                },
                object: function () {
                    return angular.copy($scope.config);
                },
                config: function(){
                    return $scope.config;

                },
                buttonText: function() {
                    return "Save";
                }
            }
        });

        modalInstance.result.then(function (scanners) {
            $scope.config.scanners = scanners;
            $scope.$parent.scanners = scanners;
            $scope.successMessage = "Successfully configured graph";
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };
});

myAppModule.controller('GraphConfigModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, url, buttonText, deleteUrl, timeoutService) {

    $scope.object = object;
    $scope.config = config;
    $scope.buttonText = buttonText;
    $scope.loading = false;

    $scope.ok = function (valid) {

        if (valid) {
            timeoutService.timeout();
            $scope.loading = true;
            angular.forEach($scope.object, function(value){
                threadFixModalService.post(url, value).
                    success(function(data, status, headers, config) {
                        timeoutService.cancel();

                        $scope.loading = false;

                        if (data.success) {
                            $modalInstance.close(data.object);
                        } else {
                            if (data.errorMap) {
                                for (var index in data.errorMap) {
                                    if (data.errorMap.hasOwnProperty(index)) {

                                        if (data.errorMap[index] === 'errors.self.certificate') {
                                            $scope.showKeytoolLink = true;
                                        } else {
                                            $scope.object[index + "_error"] = data.errorMap[index];
                                        }
                                    }
                                }
                            } else {
                                $scope.error = "Failure. Message was : " + data.message;
                            }
                        }
                    }).
                    error(function(data, status, headers, config) {
                        timeoutService.cancel();
                        $scope.loading = false;
                        $scope.error = "Failure. HTTP status was " + status;
                    });
            });
        }
        $rootScope.$broadcast('vulnChanged', null);
    };

    $scope.ind = 0;
    $scope.setCurrentIndex = function(indx){
        $scope.ind = indx;
    };

    $scope.getCurrentIndex = function(){

        return $scope.ind;
    };

    $scope.focusInput = true;

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name);
    };

    $scope.cancel = function () {
        timeoutService.cancel();
        $modalInstance.dismiss('cancel');
    };
});
