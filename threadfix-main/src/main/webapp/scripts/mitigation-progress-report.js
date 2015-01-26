var myAppModule = angular.module('threadfix');

myAppModule.controller('MitigationProgressReport', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

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

    var scannerNames = [];
    var scanID = [];
    var closed = [];
    var criticalO = [];
    var highO = [];
    var medO = [];
    var lowO = [];
    var infoO = [];
    var auditO = [];
    var criticalC = [];
    var highC = [];
    var medC = [];
    var lowC = [];
    var infoC = [];
    var auditC = [];
    var totalNumVuln = 0;
    var scannerN = [];
    var scannerC = [];
    var scannerH = [];
    var scannerM = [];
    var scannerL = [];
    var scannerI = [];
    var scannerA = [];
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

    var calculatesLevelsOpen = function(index, level){
        switch (level){
            case 1:
                infoO[index]++;
                break;
            case 2:
                lowO[index]++;
                break;
            case 3:
                medO[index]++;
                break;
            case 4:
                highO[index]++;
                break;
            case 5:
                criticalO[index]++;
                break;
            case 6:
                auditO[index]++;
        }
    };

    var calculatesLevelsClosed = function(index, level){
        switch (level){
            case 0:
                closed[index]++;
                break;
            case 1:
                infoC[index]++;
                break;
            case 2:
                lowC[index]++;
                break;
            case 3:
                medC[index]++;
                break;
            case 4:
                highC[index]++;
                break;
            case 5:
                criticalC[index]++;
                break;
            case 6:
                auditC[index]++;
        }
    };

    // TODO for Fortify SSC
    var getRemote = function(){
        $http.post(tfEncoder.encode("/graphConfig/remote/" + $scope.$parent.appId)).
            success(function(data, status, headers, config){
                $scope.remoteScan = data.object.remote;

                scannerNames.push($scope.remoteScan.scannerName);
                scanID.push(0); //TODO fix JSON
                closed.push(0);
                criticalC.push(0);
                criticalO.push($scope.remoteScan.numberCriticalVulnerabilities);

                calculatesLevelsOpen(scannerNames.indexOf($scope.remoteScan.scannerName), 5);
                highC.push(0);
                highO.push($scope.remoteScan.numberHighVulnerabilities);

                calculatesLevelsOpen(scannerNames.indexOf($scope.remoteScan.scannerName), 4);
                medC.push(0);
                medO.push($scope.remoteScan.numberMediumVulnerabilities);

                calculatesLevelsOpen(scannerNames.indexOf($scope.remoteScan.scannerName), 3);
                lowC.push(0);
                lowO.push($scope.remoteScan.numberLowVulnerabilities);

                calculatesLevelsOpen(scannerNames.indexOf($scope.remoteScan.scannerName), 2);
                infoC.push(0);
                infoO.push($scope.remoteScan.numberInfoVulnerabilities);

                calculatesLevelsOpen(scannerNames.indexOf($scope.remoteScan.scannerName), 1);
                auditC.push(0);
                auditO.push(0); //TODO fix JSON

                totalNumVuln += $scope.remoteScan.numberTotalVulnerabilities;
            })
    };

    var getData = function(){
        var parameters = angular.copy($scope.parameters);
        $http.post(tfEncoder.encode("/graphConfig/table"), parameters).
            success(function(data, status, headers, config) {
                $scope.open = data.object.open;
                $scope.closed = data.object.closed;

                if($scope.closed.length > 0) {
                    angular.forEach($scope.closed, function (value) {
                        if (scannerNames.indexOf(value.findings[0].scannerName) == -1) {
                            scannerNames.push(value.findings[0].scannerName);
                            scanID.push(value.findings[0].scanId);
                            closed.push(0);
                            criticalC.push(0);
                            highC.push(0);
                            medC.push(0);
                            lowC.push(0);
                            infoC.push(0);
                            auditC.push(0);
                            criticalO.push(0);
                            highO.push(0);
                            medO.push(0);
                            lowO.push(0);
                            infoO.push(0);
                            auditO.push(0);
                        }
                        calculatesLevelsClosed(scannerNames.indexOf(value.findings[0].scannerName), 0);
                        calculatesLevelsClosed(scannerNames.indexOf(value.findings[0].scannerName), value.genericSeverity.intValue);
                        totalNumVuln++;
                    });
                }

                angular.forEach($scope.open, function(value){
                    if(scannerNames.indexOf(value.findings[0].scannerName) == -1) {
                        scannerNames.push(value.findings[0].scannerName);
                        scanID.push(value.findings[0].scanId);
                        criticalO.push(0);
                        highO.push(0);
                        medO.push(0);
                        lowO.push(0);
                        infoO.push(0);
                        auditO.push(0);
                        closed.push(0);
                        criticalC.push(0);
                        highC.push(0);
                        medC.push(0);
                        lowC.push(0);
                        infoC.push(0);
                        auditC.push(0);
                    }

                    calculatesLevelsOpen(scannerNames.indexOf(value.findings[0].scannerName), value.genericSeverity.intValue);
                    totalNumVuln++;
                });

                $scope.results = [];

                var i;
                for(i = 0; i < scannerNames.length; i++){
                    $scope.scan.scannerNames = scannerNames[i];
                    $scope.scan.scanId = scanID[i];
                    $scope.scan.total = criticalO[i] + highO[i] + medO[i] + lowO[i] + infoO[i] + auditO[i] + closed[i];
                    $scope.scan.closed = closed[i];
                    $scope.scan.criticalO = criticalO[i];
                    $scope.scan.highO = highO[i];
                    $scope.scan.medO = medO[i];
                    $scope.scan.lowO = lowO[i];
                    $scope.scan.infoO = infoO[i];
                    $scope.scan.auditO = auditO[i];
                    $scope.scan.criticalC = criticalC[i];
                    $scope.scan.highC = highC[i];
                    $scope.scan.medC = medC[i];
                    $scope.scan.lowC = lowC[i];
                    $scope.scan.infoC = infoC[i];
                    $scope.scan.auditC = auditC[i];
                    $scope.results.push(angular.copy($scope.scan));
                }

                angular.forEach($scope.config, function(value){
                    if(value.criticalVulns == true || value.highVulns == true || value.mediumVulns == true || value.lowVulns == true || value.infoVulns == true || value.auditable == true) {
                        scannerN.push(value.name);
                        scannerC.push(value.criticalVulns);
                        scannerH.push(value.highVulns);
                        scannerM.push(value.mediumVulns);
                        scannerL.push(value.lowVulns);
                        scannerI.push(value.infoVulns);
                        scannerA.push(value.auditable);
                    }
                });

                var calcPercent = function(levelO, levelC){
                    if(levelC == 0 && levelO == 0) {
                        avg++;
                        $scope.totalCount += 100;
                        return 100;
                    }
                    else {
                        avg++;
                        $scope.totalCount += (levelC / (levelO + levelC)) * 100;
                        return (levelC / (levelO + levelC)) * 100;
                    }
                };
                $scope.totalCount = 0;
                var avg = 0;

                for(i = 0; i < scannerN.length; i++){
                    var scannerIndex = 0;
                    for(var j = 0; j < $scope.results.length; j ++){
                        if($scope.results[j].scannerNames.indexOf(scannerN[i]) != -1 )
                            scannerIndex = j;
                    }
                    if(scannerIndex == -1) {
                        scannerN[i] = null;
                        scannerC[i] = null;
                        scannerH[i] = null;
                        scannerM[i] = null;
                        scannerL[i] = null;
                        scannerI[i] = null;
                        scannerA[i] = null;
                    }
                    $scope.activeScanners.name = scannerN[i];
                    if(scannerC[i] == true)
                        $scope.activeScanners.critical = calcPercent($scope.results[scannerIndex].criticalO, $scope.results[scannerIndex].criticalC);
                    else
                        $scope.activeScanners.critical = null;
                    if(scannerH[i] == true)
                        $scope.activeScanners.high = calcPercent($scope.results[scannerIndex].highO, $scope.results[scannerIndex].highC);
                    else
                        $scope.activeScanners.high = null;
                    if(scannerM[i] == true)
                        $scope.activeScanners.medium = calcPercent($scope.results[scannerIndex].medO, $scope.results[scannerIndex].medC);
                    else
                        $scope.activeScanners.medium = null;
                    if(scannerL[i] == true)
                        $scope.activeScanners.low = calcPercent($scope.results[scannerIndex].lowO, $scope.results[scannerIndex].lowC);
                    else
                        $scope.activeScanners.low = null;
                    if(scannerI[i] == true)
                        $scope.activeScanners.info = calcPercent($scope.results[scannerIndex].infoO, $scope.results[scannerIndex].infoC);
                    else
                        $scope.activeScanners.info = null;
                    if(scannerA[i] == true)
                        $scope.activeScanners.audit = calcPercent($scope.results[scannerIndex].auditO, $scope.results[scannerIndex].auditC);
                    else
                        $scope.activeScanners.audit = null;
                    $scope.activeResults.push(angular.copy($scope.activeScanners));
                }

                $scope.totalCount = $scope.totalCount / avg;

                var width = 400;
                var height = 400;
                var margin = {"left": 30, "bottom": 40, "right": 5};

                // creating the main svg
                var svg = d3.select("#mitRep")
                    .append("svg")
                    .attr("width", width)
                    .attr("height", height)
                    .attr("class", "svg");

                svg.selectAll('*').remove();

                // x scale
                var xScale = d3.scale.linear()
                    .domain([0, totalNumVuln + 1])
                    .range([0, width - margin.left - margin.right]);

                var xAxis = d3.svg.axis()
                    .scale(xScale)
                    .ticks(totalNumVuln / 2)
                    .orient("bottom");

                // y scale
                var yScale = d3.scale.linear()
                    .domain([0, totalNumVuln + 1])
                    .range([height - margin.bottom, 0]);

                var yAxis = d3.svg.axis()
                    .scale(yScale)
                    .ticks(totalNumVuln)
                    .orient("left");

                svg.append("g")
                    .attr("class", "axis")
                    .attr("transform", "translate(20," + (height - 15) + ")")
                    .style({ 'stroke': 'white', 'fill': 'none', 'stroke-width': '2px'})
                    .call(xAxis);

                // x-label
                svg.append("text")
                    .attr("x", 200)
                    .attr("y", 390)
                    .attr("class", "axis wcm-label")
                    .text("Risk")
                    .attr("font-size", "12px")
                    .attr("font-weight", "bold")
                    .attr("fill", "black");

                svg.append("g")
                    .attr("class", "axis")
                    .attr("transform", "translate(15, 5)")
                    .style({ 'stroke': 'white', 'fill': 'none', 'stroke-width': '2px'})
                    .call(yAxis);

                // y-label
                svg.append("text")
                    .attr("x", 10)
                    .attr("y", 200)
                    .attr("class", "axis wcm-label")
                    .text("Triage")
                    .attr("font-size", "12px")
                    .attr("fill", "black")
                    .attr("font-weight", "bold")
                    .attr("transform", "rotate(270 10,200)");

                var quadrant_group = svg.append("g")
                    .attr("transform", "translate(" + margin.left + ",0)");

                var quadrant_border = quadrant_group.append("rect")
                    .attr("x", 0)
                    .attr("y", 0)
                    .attr("width", width - margin.left - margin.right)
                    .attr("height", height - margin.bottom)
                    .attr("rx", 20)
                    .attr("ry", 20)
                    .attr("class", "quadrant_border")
                    .attr("fill", "white")
                    .style({'stroke': '#D0D0D0', 'stroke-width': 1});

                // creating quadrant descriptions
                quadrant_group.append("text")
                    .attr("x", xScale(25))
                    .attr("y", yScale(25))
                    .attr("text-anchor", "middle")
                    .text("")
                    .attr("class", "quad-label");

                quadrant_group.append("text")
                    .attr("x", xScale(25))
                    .attr("y", yScale(75))
                    .attr("text-anchor", "middle")
                    .text("")
                    .attr("class", "quad-label");

                quadrant_group.append("text")
                    .attr("x", xScale(75))
                    .attr("y", yScale(25))
                    .attr("text-anchor", "middle")
                    .text("")
                    .attr("class", "quad-label");

                quadrant_group.append("text")
                    .attr("x", xScale(75))
                    .attr("y", yScale(75))
                    .attr("text-anchor", "middle")
                    .text("")
                    .attr("class", "quad-label");

                // creating the dividers
                quadrant_group.append("line")
                    .attr("x1", 0)
                    .attr("y1", yScale(totalNumVuln / 2))
                    .attr("x2", xScale(totalNumVuln + 1))
                    .attr("y2", yScale(totalNumVuln / 2))
                    .attr("class", "divider")
                    .style({'stroke': '#D0D0D0', 'stroke-width': 1});

                quadrant_group.append("line")
                    .attr("x1", xScale(totalNumVuln / 2))
                    .attr("y1", 0)
                    .attr("x2", xScale(totalNumVuln / 2))
                    .attr("y2", yScale(0))
                    .attr("class", "divider")
                    .style({'stroke': '#D0D0D0', 'stroke-width': 1});

                // xline
                var gradient = svg.append("defs")
                    .append("linearGradient")
                    .attr("id", "gradient")
                    .attr("x1", "0%")
                    .attr("y1", "10%")
                    .attr("x2", "95%")
                    .attr("y2", "10%")
                    .attr("spreadMethod", "pad");

                gradient.append("stop")
                    .attr("offset", "0%")
                    .attr("stop-color", "#ff0000")
                    .attr("stop-opacity", 10);

                gradient.append("stop")
                    .attr("offset", "75%")
                    .attr("stop-color", "#FFCC00")
                    .attr("stop-opacity", 100);

                gradient.append("stop")
                    .attr("offset", "100%")
                    .attr("stop-color", "#00ff00")
                    .attr("stop-opacity", 1);

                svg.append("rect")
                    .attr("width", 368)
                    .attr("height", 10)
                    .attr("x", 30)
                    .attr("y", 365)
                    .attr("rx", 10)
                    .attr("ry", 10)
                    .style("fill", "url(#gradient)");

                // yline
                var gradient = svg.append("defs")
                    .append("linearGradient")
                    .attr("id", "gradient1")
                    .attr("x1", "90%")
                    .attr("y1", "0%")
                    .attr("x2", "90%")
                    .attr("y2", "85%")
                    .attr("spreadMethod", "pad");

                gradient.append("stop")
                    .attr("offset", "0%")
                    .attr("stop-color", "#00ff00")
                    .attr("stop-opacity", 1);

                gradient.append("stop")
                    .attr("offset", "50%")
                    .attr("stop-color", "#FFCC00")
                    .attr("stop-opacity", 100);

                gradient.append("stop")
                    .attr("offset", "100%")
                    .attr("stop-color", "#ff0000")
                    .attr("stop-opacity", 10);

                svg.append("rect")
                    .attr("width", 10)
                    .attr("height", 360)
                    .attr("x", 15)
                    .attr("y", 0)
                    .attr("rx", 10)
                    .attr("ry", 10)
                    .style("fill", "url(#gradient1)");

                quadrant_group.selectAll("circle")
                    .data($scope.results)
                    .enter()
                    .append("circle")
                    .attr("cx", function(d) {
                        var ind = -1;
                        var criticalMit = 0;
                        var highMit = 0;
                        var medMit = 0;
                        var lowMit = 0;
                        var infoMit = 0;
                        var auditMit = 0;
                        if($scope.config.length > 0) {
                            angular.forEach($scope.config, function (value) {
                                if (value.name == d.scannerNames) {
                                    ind = $scope.config.indexOf(value);
                                }
                            });

                            if ($scope.config[ind].criticalVulns == true) {
                                criticalMit += d.criticalO;
                            }
                            if ($scope.config[ind].highVulns == true) {
                                highMit += d.highO;
                            }
                            if ($scope.config[ind].mediumVulns == true) {
                                medMit += d.medO;
                            }
                            if ($scope.config[ind].lowVulns == true) {
                                lowMit += d.lowO;
                            }
                            if ($scope.config[ind].infoVulns == true) {
                                infoMit += d.infoO;
                            }
                            if ($scope.config[ind].auditable == true) {
                                auditMit += d.auditableO;
                            }
                        }
                        if((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) > 0)
                        {
                            if(d.closed == 0)
                                return xScale(2);
                            else if(d.closed < d.total && ((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) + d.closed) == d.total)
                                return xScale((d.closed * (totalNumVuln / d.total)) - ((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) * (totalNumVuln / 2)));
                            else
                                return xScale(d.closed  * ((totalNumVuln - (criticalMit + highMit + medMit + lowMit + infoMit + auditMit)) / d.total));
                        }
                        else if((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) == 0) {
                            if (d.closed == d.total)
                                return xScale(totalNumVuln - 1);
                            else
                                return xScale((totalNumVuln / 2) + 1 + (d.closed / 2));
                        }
                        else
                        {
                            return xScale(d.closed * (totalNumVuln / d.total));
                        }
                    })
                    .attr("cy", function(d) {
                        var ind = -1;
                        var criticalMit = 0;
                        var highMit = 0;
                        var medMit = 0;
                        var lowMit = 0;
                        var infoMit = 0;
                        var auditMit = 0;
                        if($scope.config.length > 0) {
                            angular.forEach($scope.config, function (value) {
                                if (value.name == d.scannerNames)
                                    ind = $scope.config.indexOf(value);
                            });
                            if ($scope.config[ind].criticalVulns == true) {
                                criticalMit += d.criticalO;
                            }
                            if ($scope.config[ind].highVulns == true) {
                                highMit += d.highO;
                            }
                            if ($scope.config[ind].mediumVulns == true)
                                medMit += d.medO;
                            if ($scope.config[ind].lowVulns == true) {
                                lowMit += d.lowO;
                            }
                            if ($scope.config[ind].infoVulns == true) {
                                infoMit += d.infoO;
                            }
                            if ($scope.config[ind].auditable == true) {
                                auditMit += d.auditableO;
                            }
                        }
                        if((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) > 0)
                        {
                            if(d.closed == 0)
                                return yScale(2);
                            else if(d.closed < d.total)
                                return yScale(d.closed  * ((totalNumVuln - (criticalMit + highMit + medMit + lowMit + infoMit + auditMit)) / d.total));
                        }
                        else if((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) == 0) {
                            if (d.closed == d.total)
                                return yScale(totalNumVuln - 1);
                            else
                                return yScale((totalNumVuln / 2) + 1 + (d.closed / 2));
                        }
                        else
                        {
                            return yScale(d.closed * (totalNumVuln / d.total));
                        }

                    })
                    .attr("r", function(d) {
                        return 4;
                    })
                    .attr("title", function(d){return "Name: " + d.scannerNames + "\nTotal: " + d.total  +
                        "\nClosed: " + d.closed + "\nCritical: " + d.criticalO + "\nHigh: " + d.highO + "\nMedium: " +
                        d.medO + "\nLow: " + d.lowO + "\nInfo: " + d.infoO})
                    .style("cursor", "pointer")
                    .on("click", function(d){return $scope.viewScan(d.scanId)})
                    .style("fill", function(d){
                        if(d.criticalO > 0){
                            return "#F7280C";
                        }
                        else if(d.highO > 0){
                            return "#F27421";
                        }
                        else if(d.medO > 0){
                            return "#EFD20A";
                        }
                        else if(d.lowO > 0){
                            return "#458A37";
                        }
                        else if(d.infoO){
                            return "#014B6E";
                        }
                        else
                            return "lightgreen";
                    });

                quadrant_group.selectAll("#mitRep")
                    .data([1])
                    .enter()
                    .append("image")
                    .attr("xlink:href", "../../../images/eye.ico")
                    .attr("width", 20)
                    .attr("height", 20)
                    .attr("x",335)
                    .attr("y",335)
                    .style("opacity", 0.5)
                    .style("cursor", "pointer")
                    .on("click", function() {
                        return $scope.showEditModal();
                    });
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
