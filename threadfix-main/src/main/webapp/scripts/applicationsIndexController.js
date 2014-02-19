var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationsIndexController', function($scope, $log, $modal, $upload, threadfixAPIService) {

    // Initialize
    $scope.initialized = false;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    // since we need the csrfToken to make the request, we need to wait until it's initialized
    $scope.$watch('csrfToken', function() {
        threadfixAPIService.getTeams($scope.csrfToken).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                if (data.success) {
                    $scope.teams = data.object;
                    $scope.teams.sort(nameCompare)

                    if ($scope.teams.length == 0) {
                        $scope.openTeamModal();
                    }
                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });
    // Table animations

    $scope.toggle = function(team) {

        if (typeof team.expanded === "undefined") {
            team.expanded = false;
        }

        if (team.expanded) {
            team.expanded = false;
        } else {
            team.expanded = true;
        }

        loadGraph(team);
    }

    $scope.expand = function() {
        $scope.teams.forEach(function(team) {
            team.expanded = true;
            loadGraph(team);
        });
    }

    $scope.contract = function() {
        $scope.teams.forEach(function(team) {
            team.expanded = false;
        });
    }

    var loadGraph = function(team) {

        if (team.report == null) {

            var failureDiv = '<div class="" style="margin-top:10px;margin-right:20px;width:300px;height:200px;text-align:center;line-height:150px;">Failed to load report.</div>';

            threadfixAPIService.loadReport(team).
                success(function(data, status, headers, config) {

                    // TODO figure out Jasper better, it's a terrible way to access the report images.
                    var matches = data.match(/(<img src="\/jasperimage\/.*\/img_0_0_0" style="height: 250px" alt=""\/>)/);
                    if (matches !== null && matches[1] !== null) {
                        team.report = matches[1];
                    } else {
                        team.report = failureDiv;
                    }
                }).
                error(function(data, status, headers, config) {

                    // TODO improve error handling and pass something back to the users
                    team.report = failureDiv;
                });
        }
    }

    // Modal functions

    $scope.openTeamModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newTeamModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return "/organizations/modalAdd" + $scope.csrfToken;
                },
                object: function() {
                    return {};
                }
            }
        });

        modalInstance.result.then(function (newTeam) {

            $scope.teams.push(newTeam);

            $scope.teams.sort(nameCompare);

            $scope.successMessage = "Successfully added team " + newTeam.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openAppModal = function (team) {

        var application = {
            team: {
                id: team.id,
                name: team.name
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
                    return "/organizations/" + team.id + "/modalAddApp" + $scope.csrfToken;
                },
                object: function () {
                    return application;
                }
            }
        });

        modalInstance.result.then(function (newApplication) {

            if (team.applications == null) {
                team.applications = [];
            }

            team.applications.push(newApplication);

            team.applications.sort(nameCompare);

            team.expanded = true;
            loadGraph(team);

            $scope.successMessage = "Successfully added application " + newApplication.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showUploadForm = function(team, app) {
        var modalInstance = $modal.open({
            templateUrl: 'uploadScanForm.html',
            controller: 'UploadScanController',
            resolve: {
                url: function() {
                    return "/organizations/" + team.id + "/applications/" + app.id + "/upload/remote" + $scope.csrfToken;
                }
            }
        });

        modalInstance.result.then(function (newTeam) {
            $log.info("Successfully uploaded scan.");
            $log.successMessage = "Successfully uploaded scan.";
            team = newTeam
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });

    }

    $scope.onFileSelect = function(team, app, $files) {
        //$files: an array of files selected, each file has name, size, and type.
        for (var i = 0; i < $files.length; i++) {
            var file = $files[i];
            $scope.upload = $upload.upload({
                url: "/organizations/" + team.id + "/applications/" + app.id + "/upload/remote" + $scope.csrfToken,
                method: "POST",
                // headers: {'headerKey': 'headerValue'},
                // withCredentials: true,
                file: file
                // file: $files, //upload multiple files, this feature only works in HTML5 FromData browsers
                /* set file formData name for 'Content-Desposition' header. Default: 'file' */
                //fileFormDataName: myFile, //OR for HTML5 multiple upload only a list: ['name1', 'name2', ...]
                /* customize how data is added to formData. See #40#issuecomment-28612000 for example */
                //formDataAppender: function(formData, key, val){} //#40#issuecomment-28612000
            }).progress(function(evt) {
                console.log('percent: ' + parseInt(100.0 * evt.loaded / evt.total));
            }).success(function(data, status, headers, config) {
                if (data.success) {
                    // TODO pass in team with new stats
                    $scope.successMessage = "Scan was successfully uploaded to application " + app.name;
                } else {
                    $scope.errorMessage = "Scan upload was unsuccessful. Message was " + data.message;
                }
            });
        }
    };

});
