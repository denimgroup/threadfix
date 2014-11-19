var threadfixModule = angular.module('threadfix')

threadfixModule.factory('reportExporter', function(reportConstants) {

    var reportExporter = {};

    reportExporter.exportCSV = function() {
    };

    reportExporter.exportPDF = function(d3, exportInfo, width, height, name) {
        var svg = d3.select("svg");
        d3.selectAll("svg").each(function(d, i) {

            if (d3.select(this).attr("id") === exportInfo.svgId)
                svg = d3.select(this);

            console.log(d3.select(this).attr("id"));
        });
        reportExporter.exportPDFSvg(d3, svg, width, height, name);
    }

    reportExporter.exportPDFSvg = function(d3, svg, width, height, name) {
        var node = svg
            .attr("version", 1.1)
            .attr("xmlns", "http://www.w3.org/2000/svg")
            .node();

        styles(node);

        var html = node.parentNode.innerHTML;

        var imgsrc = 'data:image/svg+xml;base64,'+ btoa(html);
        var img = '<img src="'+imgsrc+'">';
        d3.select("#svgdataurl").html(img);

        var canvas = document.createElement("canvas");
        canvas.width = (svg.attr("width")) ? svg.attr("width") : width;
        canvas.height = (svg.attr("height")) ? svg.attr("height") : height;
        var context = canvas.getContext("2d");

        var image = new Image();
        image.src = imgsrc;
        image.onload = function() {
            context.drawImage(image, 0, 0);

            var canvasdata = canvas.toDataURL("image/png");

            var pngimg = '<img src="'+canvasdata+'">';
            d3.select("#pngdataurl").html(pngimg);

            var a = document.createElement("a");
            a.download = name + ".png";
            a.href = canvasdata;
            a.click();
        };

    };

    var styles = function(dom) {
        var used = "";
        var sheets = document.styleSheets;
        for (var i = 0; i < sheets.length; i++) {
            var rules = sheets[i].cssRules;
            for (var j = 0; j < rules.length; j++) {
                var rule = rules[j];
                if (typeof(rule.style) != "undefined") {
                    try {
                        var elems = dom.querySelectorAll(rule.selectorText);
                        if (elems.length > 0) {
                            used += rule.selectorText + " { " + rule.style.cssText + " }\n";
                        }
                    } catch (x) {
                        console.log(x);
                    }
                }
            }
        };

        var s = document.createElement('style');
        s.setAttribute('type', 'text/css');
        s.innerHTML = "<![CDATA[\n" + used + "\n]]>";

        var defs = document.createElement('defs');
        defs.appendChild(s);
        dom.insertBefore(defs, dom.firstChild);
    };

    return reportExporter;
});

threadfixModule.factory('d3Service', function() {

    var d3Service = {};

    d3Service.getColorScale = function(d3, range) {
        return d3.scale.ordinal()
            .range(range);
    }

    d3Service.getScaleOrdinalRangeBand = function(d3, range, scale) {
        return d3.scale.ordinal()
            .rangeRoundBands(range, scale);
    }

    d3Service.getScaleLinearRange = function(d3, range) {
        return d3.scale.linear()
            .rangeRound(range);
    }

    d3Service.getAxis = function(d3, scale, orient) {
        return  d3.svg.axis()
            .scale(scale)
            .tickSize(3)
            .orient(orient);
    };

    d3Service.getAxisFormat = function(d3, scale, orient, format) {
        return  d3Service.getAxis(d3, scale, orient)
            .tickFormat(format);
    };

    d3Service.getSvg = function(d3, elementId, w, h) {
        return d3.select(elementId).append("svg")
            .attr("width", w)
            .attr("height", h);
    }

    d3Service.getExistingSvg = function(d3, elementId, w, h) {
        var svgs = d3.select(elementId).selectAll("svg");
        if (svgs.length>0 && svgs[0].length>0)
            return svgs;
        return d3.select(elementId).append("svg")
            .attr("width", w)
            .attr("height", h);
    }

    d3Service.getTip = function(d3, clazz, offset, tipId) {
        return d3.tip()
            .attr('class', clazz)
            .attr('id', tipId)
            .offset(offset);
    }

    return d3Service;

});

threadfixModule.factory('reportConstants', function() {

    var reportConstants = {};

    reportConstants.vulnTypeColorList = ["#014B6E", "#458A37", "#EFD20A", "#F27421", "#F7280C"];
    reportConstants.vulnTypeList = ["Info", "Low", "Medium", "High", "Critical"];
    reportConstants.vulnTypeColorMap = {
        Info: reportConstants.vulnTypeColorList[0],
        Low: reportConstants.vulnTypeColorList[1],
        Medium: reportConstants.vulnTypeColorList[2],
        High: reportConstants.vulnTypeColorList[3],
        Critical: reportConstants.vulnTypeColorList[4]
    };
    reportConstants.reportTypes = {
        trending: {
            id: 9,
            name: "trendingTrendingGraph"
        },
        compliance: {
            id: 11,
            name: "complianceTrendingGraph"
        },
        complianceEnterprise: {
            id: 12,
            name: "complianceEnterpriseTrendingGraph"
        }
    };

    return reportConstants;

});

threadfixModule.factory('reportUtilities', function() {

    var reportUtilities = {};
    var drawingDuration = 500;

    reportUtilities.drawTitle = function(svg, w, label, title, y) {
        var teams, apps, tags;
        if (label) {
            teams = label.teams;
            apps = label.apps;
            tags = label.tags;
        }
        svg.append("g")
            .append("text")
            .attr("x", w/2)
            .attr("y", y)
            .attr("class", "header")
            .attr("id", title+"_Title")
            .text(title)
        var i = 0;
        if (teams) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20)
                .attr("class", "title")
                .attr("id", title+"_Teams")
                .text("Team: " + teams);
            i++;
        }
        if (apps) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20 + i*15)
                .attr("class", "title")
                .attr("id", title+"_Apps")
                .text("Application: " + apps);
            i++;
        }
        if (tags) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20 + i*15)
                .attr("class", "title")
                .attr("id", title+"_Tags")
                .text("Tags: " + tags)
        }
    }

    reportUtilities.createTeamAppNames = function($scope) {
        var teams;
        var apps;
        var tags;
        if ($scope.parameters.teams && $scope.parameters.applications)
            if ($scope.parameters.teams.length === 0
                && $scope.parameters.applications.length === 0) {
                teams = "All";
                apps = "All";
            } else {
                if ($scope.parameters.teams.length > 0) {
                    teams = $scope.parameters.teams[0].name;
                }
                var i;
                for (i=1; i<$scope.parameters.teams.length; i++) {
                    teams += ", " + $scope.parameters.teams[i].name;
                }

                if ($scope.parameters.applications.length > 0) {
                    apps = $scope.parameters.applications[0].name;
                }
                for (i=1; i<$scope.parameters.applications.length; i++) {
                    apps += ", " + $scope.parameters.applications[i].name;
                }
            }

        if ($scope.parameters.tags) {
            if ($scope.parameters.tags.length === 0) {
                tags = "All";
            } else {
                if ($scope.parameters.tags.length > 0) {
                    tags = $scope.parameters.tags[0].name;
                }
                var i;
                for (i=1; i<$scope.parameters.tags.length; i++) {
                    tags += ", " + $scope.parameters.tags[i].name;
                }
            }
        }

        if (!$scope.title)
            $scope.title = {};
        $scope.title.teams = teams;
        $scope.title.apps = apps;
        $scope.title.tags = tags;
    }

    reportUtilities.drawTable = function(d3, tableData, divId) {

        var table = d3.select("#" + divId).select("table").attr("class", "table"),
            thead = d3.select("#" + divId).select("thead"),
            tbody = d3.select("#" + divId).select("tbody");

        thead.selectAll('*').remove();
        tbody.selectAll('*').remove();


        thead.selectAll("th")
            .data(d3.keys(tableData[0]))
            .enter().append("th")
            .attr("id", function(d){return d})
            .text(function(d){return d});

        // First create the table rows
        var tr = tbody.selectAll("tr")
            .data(tableData).enter().append("tr")
            .attr("id", function(d, index){return index});

        // Now create the table cells
        var td = tr.selectAll("td")
            .data(function(d){return d3.values(d)})
            .enter().append("td")
            .attr("id", function(d, index){return index})
            .text(function(d) {return d});
    }

    return reportUtilities;

});

threadfixModule.factory('trendingUtilities', function(reportUtilities) {

    var trendingUtilities = {};
    var startIndex = -1, endIndex = -1;
    var firstHashInList, lastHashInList;

    trendingUtilities.getFirstHashInList = function(){
        return firstHashInList;
    };

    trendingUtilities.getLastHashInList = function() {
        return lastHashInList;
    };

    trendingUtilities.refreshScans = function($scope){
        $scope.loading = true;
        $scope.noData = false;
        $scope.trendingScansData = [];
        reportUtilities.createTeamAppNames($scope);

        trendingUtilities.filterByTime($scope);
        if ($scope.filterScans.length === 0) {
            $scope.noData = true;
            $scope.loading = false;
            return;
        }
        trendingUtilities.updateDisplayData($scope);
        if ($scope.trendingScansData.length === 0) {
            $scope.noData = true;
            $scope.loading = false;
            return;
        }
        $scope.loading = false;
    };

    trendingUtilities.updateDisplayData = function($scope){
        var hashBefore, hashAfter;
        firstHashInList = null, lastHashInList = null;
        reportUtilities.createTeamAppNames($scope);
        $scope.trendingScansData = [];
        $scope.totalVulnsByChannelMap = {};
        $scope.infoVulnsByChannelMap = {};
        $scope.lowVulnsByChannelMap = {};
        $scope.mediumVulnsByChannelMap = {};
        $scope.highVulnsByChannelMap = {};
        $scope.criticalVulnsByChannelMap = {};
        if (startIndex!==-1 && endIndex!==-1) {
            $scope.filterScans.forEach(function(scan, index){
                var _scan = trendingUtilities.filterDisplayData(scan, $scope);

                if (startIndex == index + 1)
                    hashBefore = _scan;
                if (index == endIndex + 1)
                    hashAfter = _scan;
                if ((startIndex===-1 || startIndex <= index)
                    && (endIndex===-1 || endIndex >= index))
                    $scope.trendingScansData.push(_scan);

            });

            if ($scope.trendingScansData.length===1 && $scope.trendingStartDate == $scope.trendingEndDate) {
                $scope.trendingEndDate = (new Date()).getTime();
                var time = new Date($scope.trendingScansData[0].importTime);
                $scope.trendingStartDate = (new Date(time.getFullYear(), time.getMonth() - 1, 1)).getTime();
            }
            if ($scope.trendingScansData.length > 0) {
                $scope.trendingScansData.unshift(createStartHash(hashBefore, $scope));
                $scope.trendingScansData.push(createEndHash(hashAfter, $scope));
            }
        }
    };

    var createStartHash = function(hashBefore, $scope) {
        var startHash = {};
        if ($scope.trendingScansData.length===0)
            return startHash;
        firstHashInList = $scope.trendingScansData[0];

        if (!hashBefore) {
            startHash.importTime=  $scope.trendingStartDate;
            var keys = Object.keys(firstHashInList);
            keys.forEach(function(key){
                if (key != "importTime")
                    startHash[key] = 0;
            });
            firstHashInList = startHash;
        } else {
            var rate1 = (firstHashInList.importTime)-(hashBefore.importTime);
            var rate2 = $scope.trendingStartDate-(hashBefore.importTime);
            startHash.importTime=  $scope.trendingStartDate;
            var keys = Object.keys(firstHashInList);
            keys.forEach(function(key){
                if (key != "importTime") {
                    var value = Math.round(hashBefore[key] + (firstHashInList[key] - hashBefore[key]) / rate1 * rate2);
                    startHash[key] = value;
                }
            });
            firstHashInList = hashBefore;
        }
        return startHash;
    }

    var createEndHash = function(hashAfter, $scope) {
        var endHash = {};
        if ($scope.trendingScansData.length===0)
            return endHash;
        lastHashInList = $scope.trendingScansData[$scope.trendingScansData.length-1];

        if (!hashAfter) {
            endHash.importTime=  $scope.trendingEndDate;
            var keys = Object.keys(lastHashInList);
            keys.forEach(function(key){
                if (key != "importTime")
                    endHash[key] = lastHashInList[key];
            });
        } else {
            var rate1 = (hashAfter.importTime)-(lastHashInList.importTime);
            var rate2 = $scope.trendingEndDate-(hashAfter.importTime);
            endHash.importTime=  $scope.trendingEndDate;
            var keys = Object.keys(lastHashInList);
            keys.forEach(function(key){
                if (key != "importTime") {
                    var value = Math.round(lastHashInList[key] + (hashAfter[key] - lastHashInList[key]) / rate1 * rate2);
                    endHash[key] = value;
                }
            });
        }
        return endHash;
    }

    trendingUtilities.filterDisplayData = function(scan, $scope) {
        var data = {};
        data.importTime = scan.importTime;
        if ($scope.parameters.showNew)
            data.New = scan.numberNewVulnerabilities;
        if ($scope.parameters.showResurfaced)
            data.Resurfaced = scan.numberResurfacedVulnerabilities;
        if ($scope.parameters.showTotal) {
            data.Total = calculateTotal(scan, $scope);
        }
        if ($scope.parameters.showClosed)
            data.Closed = scan.numberClosedVulnerabilities;
        if ($scope.parameters.showOld)
            data.Old = scan.numberOldVulnerabilities;
        if ($scope.parameters.showHidden)
            data.Hidden = scan.numberHiddenVulnerabilities;

        if ($scope.parameters.severities.info) {
            data.Info = calculateInfo(scan, $scope);
        }
        if ($scope.parameters.severities.low) {
            data.Low = calculateLow(scan, $scope);
        }
        if ($scope.parameters.severities.medium) {
            data.Medium = calculateMedium(scan, $scope);
        }
        if ($scope.parameters.severities.high) {
            data.High = calculateHigh(scan, $scope);
        }
        if ($scope.parameters.severities.critical) {
            data.Critical = calculateCritical(scan, $scope);
        }
        return data;
    }

    var calculateTotal = function(scan, $scope) {
        var adjustedTotal = scan.numberTotalVulnerabilities -
            scan.numberOldVulnerabilities +
            scan.numberOldVulnerabilitiesInitiallyFromThisChannel;
        return trendingTotal($scope.totalVulnsByChannelMap, scan, adjustedTotal);
    }

    var calculateInfo = function(scan, $scope) {
        return trendingTotal($scope.infoVulnsByChannelMap, scan, scan.numberInfoVulnerabilities);
    }

    var calculateLow = function(scan, $scope) {
        return trendingTotal($scope.lowVulnsByChannelMap, scan, scan.numberLowVulnerabilities);
    }

    var calculateMedium = function(scan, $scope) {
        return trendingTotal($scope.mediumVulnsByChannelMap, scan, scan.numberMediumVulnerabilities);
    }

    var calculateHigh = function(scan, $scope) {
        return trendingTotal($scope.highVulnsByChannelMap, scan, scan.numberHighVulnerabilities);
    }

    var calculateCritical = function(scan, $scope) {
        return trendingTotal($scope.criticalVulnsByChannelMap, scan, scan.numberCriticalVulnerabilities);
    }

    var trendingTotal = function(map, scan, newNum) {
        if (scan.applicationChannelId) {
            map[scan.applicationChannelId] = newNum;
        }

        var numTotal = newNum;
        // This code counts in the old vulns from other channels.
        for (var key in map) {
            if (map.hasOwnProperty(key)) {
                if (!scan.applicationChannelId || scan.applicationChannelId != key) {
                    numTotal += map[key];
                }
            }
        }
        return numTotal;
    }

    trendingUtilities.filterByTeamAndApp = function($scope) {

        $scope.filterScans = $scope.allScans.filter(function(scan){
            if ($scope.parameters.teams.length === 0 && $scope.parameters.applications.length === 0)
                return true;
            var i;
            for (i=0; i<$scope.parameters.teams.length; i++) {
                if (scan.team.name === $scope.parameters.teams[i].name) {
                    return true;
                }
            }
            for (i=0; i<$scope.parameters.applications.length; i++) {
                if (beginsWith($scope.parameters.applications[i].name, scan.team.name + " / ") &&
                    endsWith($scope.parameters.applications[i].name, " / " + scan.app.name)) {
                    return true;
                }
            }
            return false;
        });

    };

    trendingUtilities.filterByTag = function($scope) {

        $scope.filterScans = $scope.allScans.filter(function(scan){
            if ($scope.parameters.tags.length === 0 )
                return true;
            var i, j;
            for (i=0; i<$scope.parameters.tags.length; i++) {
                for (j=0; j<scan.applicationTags.length; j++) {
                    if (scan.applicationTags[j].name === $scope.parameters.tags[i].name) {
                        return true;
                    }
                }
            }
            return false;
        });

    };

    trendingUtilities.filterByTime = function($scope) {
        if (!$scope.filterScans || $scope.filterScans.length === 0)
            return;
        $scope.trendingStartDate = undefined;
        $scope.trendingEndDate = undefined;
        startIndex = -1; endIndex = -1;
        if ($scope.parameters.daysOldModifier) {
            $scope.trendingEndDate = new Date();
            if ($scope.parameters.daysOldModifier === "LastYear") {
                $scope.trendingStartDate = new Date($scope.trendingEndDate.getFullYear(), $scope.trendingEndDate.getMonth() - 11, 1);
            } else if ($scope.parameters.daysOldModifier === "LastQuarter") {
                $scope.trendingStartDate = new Date($scope.trendingEndDate.getFullYear(), $scope.trendingEndDate.getMonth() - 2, 1);
            };
        } else {
            if ($scope.parameters.endDate) {
                $scope.trendingEndDate = $scope.parameters.endDate;
            }
            if ($scope.parameters.startDate) {
                $scope.trendingStartDate = $scope.parameters.startDate;
            }
        };

        if (!$scope.trendingStartDate) {
            startIndex = 0;
            $scope.trendingStartDate = $scope.filterScans[0].importTime;
        }
        if (!$scope.trendingEndDate ) {
            endIndex = $scope.filterScans.length - 1;
            $scope.trendingEndDate = new Date();
        }

        $scope.filterScans.some(function(scan, index) {
            if (startIndex!==-1 && endIndex!==-1)
                return true;
            if (startIndex===-1 && $scope.trendingStartDate && $scope.trendingStartDate<=scan.importTime)
                startIndex = index;
            if (endIndex===-1 && $scope.trendingEndDate && $scope.trendingEndDate < scan.importTime)
                endIndex = index - 1;
        });

        if (startIndex===-1 && endIndex!==-1)
            startIndex = 0;
        if (startIndex!==-1 && endIndex===-1)
            endIndex = $scope.filterScans.length - 1;
    };

    var endsWith = function(str, suffix) {
        return str.indexOf(suffix, str.length - suffix.length) !== -1;
    };

    var beginsWith = function(str, prefix) {
        return str.indexOf(prefix) == 0;
    };

    trendingUtilities.resetFilters = function($scope) {
        if ($scope.savedDefaultTrendingFilter) {
            $scope.selectedFilter = $scope.savedDefaultTrendingFilter;
            $scope.parameters = JSON.parse($scope.savedDefaultTrendingFilter.json);
            if ($scope.parameters.startDate)
                $scope.parameters.startDate = new Date($scope.parameters.startDate);
            if ($scope.parameters.endDate)
                $scope.parameters.endDate = new Date($scope.parameters.endDate);
        } else
            $scope.parameters = {
                teams: [],
                applications: [],
                severities: {
                    info: true,
                    low: true,
                    medium: true,
                    high: true,
                    critical: true
                },
                showClosed: false,
                showOld: false,
                showHidden: false,
                showTotal: false,
                showNew: false,
                showResurfaced: false,
                daysOldModifier: 'LastYear',
                endDate: undefined,
                startDate: undefined
            };
    };

    return trendingUtilities;
});

