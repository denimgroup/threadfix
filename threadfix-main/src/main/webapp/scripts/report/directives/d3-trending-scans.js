var d3ThreadfixModule = angular.module('threadfix');

// Trending scans report
d3ThreadfixModule.directive('d3Trending', ['d3', 'reportExporter', 'reportUtilities', 'reportConstants',
    function(d3, reportExporter, reportUtilities, reportConstants) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: '=',
                width: '@',
                height: '@',
                margin: '=',
                tableInfo: '=',
                startDate: '=',
                endDate: '=',
                exportInfo: '=',
                svgId:'=',
                sumTableDivId:'='
            },
            link: function(scope, ele, attrs) {
                var svgWidth = scope.width,
                    svgHeight = scope.height,
                    m = scope.margin,
                    w = svgWidth - m[1] - m[3],
                    h = svgHeight - m[0] - m[2];

                var
                    stackedData,
                    _data,
                    focus,
                    focusCircles,
                    duration = 500,
                    firstScanNotReal,
                    lastScanNotReal;

                var x = d3.time.scale().range([0, w]),
                    y = d3.scale.linear().range([h, 0]);

                var xAxis = d3.svg.axis()
                    .scale(x)
                    .tickSize(3)
                    .tickFormat(function(d) {
                        return monthList[d.getMonth()] + "-" + d.getFullYear();
                    })
                    .orient("bottom");

                var yAxis = d3.svg.axis()
                    .scale(y)
                    .tickSize(3)
                    .orient("left");

                var color = d3.scale.category10();

                var svg = d3.select(ele[0]).append("svg")
                    .attr("width", svgWidth)
                    .attr("height", svgHeight)
                    .attr("id", function(){
                        return (scope.svgId) ? scope.svgId : "trendingGraph";
                    });

                svg.append("rect")
                    .attr("transform", "translate(0, 0)")
                    .attr("width", svgWidth)
                    .attr("height", svgHeight)
                    .attr("fill", "#ffffff")
                    .attr("strokeWidth", 0);

                svg = svg
                    .append("g")
                    .attr("transform", "translate(" + m[3] + "," + m[0] + ")");

                var monthList = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                var fieldOrderMap = {
                    New : 0,
                    Resurfaced: 1,
                    Closed: 2,
                    Old: 3,
                    Hidden: 4,
                    Info: 5,
                    Low: 6,
                    Medium: 7,
                    High: 8,
                    Critical: 9,
                    Total: 10
                };

                // A line generator, for the dark stroke.
                var line = d3.svg.line()
                    .x(function(d) { return x(d.date); })
                    .y(function(d) { return y(d.noOfVulns); });

                var mouserOverLine = d3.svg.area()
                    .interpolate('basis')
                    .x (function (d) { return x(d.date); })
                    .y0(function (d) { return 0; })
                    .y1(function (d) { return h; });

                // A area generator, for the dark stroke.
                var area = d3.svg.area()
                    .x(function(d) { return x(d.date); })
                    .y1(function(d) { return y(d.noOfVulns); });

                var tip =  d3.tip()
                    .attr('class', 'd3-tip')
                    .attr('id', 'areaChartTip')
                    .offset([-10, 0]);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.$watch('label', function() {
                    scope.render(scope.data);
                }, true);

                scope.render = function (reportData) {
                    if (!reportData)
                        return;
                    _data = angular.copy(reportData);

                    svg.selectAll('*').remove();

                    if (scope.label)
                        reportUtilities.drawTitle(svg, w, scope.label, "Trending Report", 30-m[0]);

                    if (_data.length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", w/2)
                            .attr("y", 70)
                            .attr("class", "warning")
                            .text("No Results Found");
                        drawTable();
                        return;
                    }

                    var colorDomain = d3.keys(_data[0]).filter(function(key){return key !== "importTime" && key !== "notRealScan";});
                    if (colorDomain.length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", w/2)
                            .attr("y", 70)
                            .attr("class", "warning")
                            .text("Select fields to display");
                        drawTable();
                        return;
                    }

                    color.domain(colorDomain);
                    svg.selectAll('*').remove();
                    drawReport();
                    drawTable();
                };

                function drawReport(){
                    if (_data.length > 0) {
                        firstScanNotReal = _data[0].notRealScan;
                        lastScanNotReal = _data[_data.length - 1].notRealScan;
                    }
                    stackedData = prepareStackedData(_data);
                    stackedData.forEach(function(s) {
                        s.maxNoOfVulns = d3.max(s.values, function(d) { return d.noOfVulns; });
                    });

                    //Sorting
                    stackedData.sort(function(a, b) {
                        return fieldOrderMap[b.key] - fieldOrderMap[a.key];
                    });

                    var noVulnsList = [];
                    stackedData = stackedData.filter(function(s){
                        if (s.maxNoOfVulns === 0)
                            noVulnsList.push(s.key);
                        return s.maxNoOfVulns > 0;
                    });

                    var stack = d3.layout.stack()
                        .values(function(d) { return d.values; })
                        .x(function(d) { return d.date; })
                        .y(function(d) { return d.noOfVulns; })
                        .out(function(d, y0, y) { d.noOfVulns0 = y0; })
                        .order("reverse");

                    stack(stackedData);

                    svg.selectAll("g")
                        .data(stackedData)
                        .enter().append("g")
                        .attr("class", "symbol");

                    var xMin = d3.min(stackedData, function(d) { return d.values[0].date; });
                    var xMax = d3.max(stackedData, function(d) { return d.values[d.values.length - 1].date; });

                    var startAxis = (scope.startDate) ? scope.startDate : xMin;
                    var endAxis = (scope.endDate) ? scope.endDate : xMax;

                    // Compute the minimum and maximum date across scans.
                    x.domain([startAxis, endAxis]);
                    y.domain([0, d3.max(stackedData[0].values.map(function(d) { return d.noOfVulns + d.noOfVulns0; }))]);

                    var diffMonths = monthDiff(new Date(startAxis), new Date(endAxis)),
                        intervalMonths = Math.round(diffMonths/6);

                    // If date span is more than a month
                    if (diffMonths > 0) {
                        intervalMonths = (intervalMonths===5 ? 4 : intervalMonths);
                        intervalMonths = (intervalMonths>6 ? 12 : intervalMonths);
                        xAxis.ticks(d3.time.month, intervalMonths);
                    } else {
                        // If time span is within a month
                        xAxis.tickFormat(function(d) {
                            return monthList[d.getMonth()] + "-" + d.getDate() + "-" + d.getFullYear().toString().substr(2,2);
                        });
                        var diffDays = Math.round((endAxis-startAxis)/(24*60*60*1000));
                        if (diffDays <=6 )
                            xAxis.ticks(d3.time.day, 1);
                        else
                            xAxis.ticks(d3.time.day, 5);
                    }

                    var g = svg.selectAll(".symbol");
                    svg.call(tip);
                    if (scope.label)
                        reportUtilities.drawTitle(svg, w, scope.label, "Trending Report", 30-m[0]);

                    // Add the x-axis.
                    svg.append("g")
                        .attr("class", "x axis")
                        .attr("transform", "translate(0," + h + ")")
                        .transition()
                        .duration(duration)
                        .call(xAxis)
                        .selectAll("text")
                        .style("text-anchor", "end")
                        .attr("transform", function(d) {
                            return "rotate(-35)"
                        });

                    // Add the y-axis.
                    svg.append("g")
                        .attr("class", "y axis")
                        .transition()
                        .duration(duration)
                        .call(yAxis);

                    focus = svg.append("g")
                        .attr("class", "focus")
                        .style("display", "none");

                    focusCircles = focus.selectAll('circle')
                        .data(stackedData)
                        .enter()
                        .append('circle')
                        .attr('class', 'circle')
                        .attr('r', 4)
                        .attr('fill', 'none')
                        .attr('stroke', function (d) { return getColor(d.key); });

                    line
                        .y(function(d) { return y(d.noOfVulns0); });

                    area
                        .y0(function(d) { return y(d.noOfVulns0); })
                        .y1(function(d) { return y(d.noOfVulns0 + d.noOfVulns); });

                    var textPosMap = {};
                    g.each(function(d) {
                        var e = d3.select(this);
                        e.selectAll(".area")
                            .data(d3.range(1))
                            .enter().insert("path", ".line")
                            .attr("class", "area")
                            .attr("id", function(){
                                return d.key + "Area";
                            })
                            .style("fill", "white")
                            .transition()
                            .duration(duration)
                            .style("fill", getColor(d.key))
                            .attr("d", area(d.values));

                        e.append("path")
                            .attr("class", "line")
                            .transition()
                            .duration(duration)
                            .style("stroke-opacity", 1)
                            .attr("d", line(d.values));

                        e.selectAll("scanCircle")
                            .data(d.values)
                            .enter()
                            .append('circle')
                            .attr('class', 'circle')
                            .attr('r', 1.5)
                            .attr('fill', 'steelblue')
                            .attr('transform', function(scan, i) {
                                if (i === 0 && firstScanNotReal)
                                    return;
                                if (i === d.values.length - 1 && lastScanNotReal)
                                    return;
                                return 'translate(' + x(scan.date) + ',' + y(scan.noOfVulns + scan.noOfVulns0) + ')';
                            })

                        e.append("text")
                            .attr("x", 15)
                            .attr("dy", ".35em")
                            .style("font-weight", "bold")
                            .transition()
                            .duration(duration)
                            .attr('fill', getColor(d.key))
                            .attr("id", function(){
                                return d.key + "Text";
                            })
                            .text(d.key)
                            .attr("transform", function() {
                                d = d.values[d.values.length - 1];
                                var y0 = Math.round(y(d.noOfVulns / 2 + d.noOfVulns0));
                                var pos, pos1;
                                var i = 0, found,j;

                                for (j=0;j<10;j++) {
                                    pos1 = (w) + "," + (y0 - j);
                                    if (textPosMap[pos1]) {
                                        found = true;
                                        break;
                                    }
                                }
                                if (found)
                                    y0 = y0-j;
                                pos = (w) + "," + (y0);

                                while (textPosMap[pos]) {
                                    i++;
                                    pos = (w) + "," + (y0+i*10);
                                }
                                textPosMap[pos] = true;
                                return "translate(" + pos + ")";
                            });
                    });

                    g.on("mouseover", function() { focus.style("display", null); })
                        .on("mouseout", function() { focus.style("display", "none"); tip.hide()})
                        .on("mousemove", mousemove);

                }

                function drawTable(){
                    if (scope.tableInfo && scope.sumTableDivId)
                        reportUtilities.drawTable(d3, scope.tableInfo, scope.sumTableDivId);
                }

                function prepareStackedData(data) {
                    return color.domain().map(function(name){
                        var values = [];
                        data.forEach(function(d){
                            values.push({date: d.importTime, noOfVulns: d[name]});
                        });
                        return {key: name, values: values};
                    })
                }

                function mousemove() {
                    var x0 = x.invert(d3.mouse(this)[0]),
                        month = Math.round(x0);
                    var time, coordObj, tips = [];

                    focusCircles.attr('transform', function (d) {

                        // Find mouse's nearest scan
                        var i;
                        if (month <= d.values[0].date)
                            i = 0;
                        else if (month >= d.values[d.values.length-1].date) {
                            i = d.values.length - 1;
                        } else {
                            for (i = 1; i< d.values.length; i++) {
                                if (d.values[i-1].date <= month && d.values[i].date >= month) {
                                    i = (d.values[i].date - month > month - d.values[i-1].date) ? i-1 : i;
                                    break;
                                }
                            }
                        }

                        if (d.values.length > 1) {
                            if (i === 0 && firstScanNotReal)
                                i= 1;
                            else if (i === d.values.length - 1 && lastScanNotReal)
                                i= i-1;
                        }

                        time = d.values[i].date;
                        tips.push("<tr><td>" + d.key + "&nbsp;</td> <td style='color:"+ getTextColor(d.key) +"'>" + d.values[i].noOfVulns + "</td></tr>");

                        focus.selectAll('path').remove();
                        focus.append("path")
                            .attr("class", "line")
                            .style("stroke-width", '0.5px')
                            .attr("d", mouserOverLine([d.values[i]]));

                        return 'translate(' + x(d.values[i].date) + ',' + y(d.values[i].noOfVulns + d.values[i].noOfVulns0) + ')';
                    });

                    tip.html(function(){
                        var date = new Date(time);
                        var tipContent = "<tr><td colspan='2' style='color:dodgerblue;text-align:center;'>" +
                            (monthList[date.getMonth()]) + " " + date.getDate() + " " + date.getFullYear() + "</td></tr>";

                        var table = '<table style="text-align:left;font-weight: bold;">' + tipContent;
                        tips.forEach(function(tip) {
                            table += tip;
                        });
                        table += "</table>";

                        return table;
                    });
                    coordObj = (focusCircles && focusCircles.length>0 && focusCircles[0] && focusCircles[0].length > 0) ?  focusCircles[0][0] : undefined;
                    tip.show(coordObj);
                }

                function monthDiff(d1, d2) {
                    var months;
                    months = (d2.getFullYear() - d1.getFullYear()) * 12 + d2.getMonth() - d1.getMonth();
                    return months <= 0 ? 0 : months;
                }

                function getColor(key) {
                    return (reportConstants.vulnTypeColorMap[key] && reportConstants.vulnTypeColorMap[key].graphColor ?
                        reportConstants.vulnTypeColorMap[key].graphColor :
                        color(getNumberFromKey(key)));
                }

                function getTextColor(key) {
                    return (reportConstants.vulnTypeColorMap[key] && reportConstants.vulnTypeColorMap[key].textColor ?
                        reportConstants.vulnTypeColorMap[key].textColor :
                        color(getNumberFromKey(key)));
                }

                scope.export = function(){

                    var teamsName = (scope.exportInfo && scope.exportInfo.teams) ? "_" + scope.exportInfo.teams : "",
                        appsName = (scope.exportInfo && scope.exportInfo.apps) ? "_" + scope.exportInfo.apps : "",
                        tagsName = (scope.exportInfo && scope.exportInfo.tags) ? "_" + scope.exportInfo.tags : "",
                        title = (scope.exportInfo && scope.exportInfo.tags) ? "Compliance_Report" : "Trending_Scans";

                    reportExporter.exportPDF(d3, scope.exportInfo, svgWidth, svgHeight,
                        title + teamsName + appsName + tagsName);

                };

            }
        }
    }]);

