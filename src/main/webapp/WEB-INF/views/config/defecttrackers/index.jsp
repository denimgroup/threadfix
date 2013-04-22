<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Trackers</title>
</head>

<body id="config">
	<h2>Defect Trackers</h2>
	
	<div id="helpText">
		A Defect Tracker is the ThreadFix link that allows the user to bundle and export 
		vulnerabilities from an Application to a Defect Tracker.
	</div>
	
	<div id="defectTableDiv">
		<%@ include file="/WEB-INF/views/config/defecttrackers/trackersTable.jsp" %>
	</div>
</body>