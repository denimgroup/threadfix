-- INSERT THE CHANNELS
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Fortify 360', 'http://www.fortify.com', '2.5.0');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Microsoft CAT.NET', 'http://msdn.microsoft.com/en-us/security/default.aspx', '1 CTP');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Checkmarx CxSuite', 'http://www.checkmarx.com/index.aspx', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Find Bugs', 'http://findbugs.sourceforge.net/', '1.3.9');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('OWASP Orizon', 'http://www.owasp.org/index.php/Category:OWASP_Orizon_Project', '1.19');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('IBM Rational AppScan Source Edition', 'http://www-01.ibm.com/software/rational/products/appscan/source/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('IBM Rational AppScan', 'http://www-01.ibm.com/software/awdtools/appscan/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Mavituna Security Netsparker', 'http://www.mavitunasecurity.com/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('WhiteHat Sentinel', 'http://www.whitehatsec.com/home/services/services.html', '-');

SET @fortify_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Fortify 360');
SET @cat_net_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Microsoft CAT.NET');
SET @checkmarx_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Checkmarx CxSuite');
SET @findbugs_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Find Bugs');
SET @orizon_channel_id := (SELECT id FROM ChannelType WHERE Name = 'OWASP Orizon');
SET @appscanse_channel_id := (SELECT id FROM ChannelType WHERE Name = 'IBM Rational AppScan Source Edition');
SET @appscan_channel_id := (SELECT id FROM ChannelType WHERE Name = 'IBM Rational AppScan');
SET @netsparker_net_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Mavituna Security Netsparker');
SET @sentinel_channel_id := (SELECT id FROM ChannelType WHERE Name = 'WhiteHat Sentinel');

-- INSERT GENERIC MAPPINGS
INSERT INTO GenericSeverity (Name) VALUES ('Critical');
INSERT INTO GenericSeverity (Name) VALUES ('High');
INSERT INTO GenericSeverity (Name) VALUES ('Medium');
INSERT INTO GenericSeverity (Name) VALUES ('Low');
INSERT INTO GenericSeverity (Name) VALUES ('Info');

SET @generic_severity_critical_id := (SELECT id FROM GenericSeverity WHERE Name = 'Critical');
SET @generic_severity_high_id := (SELECT id FROM GenericSeverity WHERE Name = 'High');
SET @generic_severity_medium_id := (SELECT id FROM GenericSeverity WHERE Name = 'Medium');
SET @generic_severity_low_id := (SELECT id FROM GenericSeverity WHERE Name = 'Low');
SET @generic_severity_info_id := (SELECT id FROM GenericSeverity WHERE Name = 'Info');


-- INSERT ChannelType SEVERITIES
-- Fortify
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Hot', 'Hot', @fortify_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Warning', 'Warning', @fortify_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Info', 'Info', @fortify_channel_id);

INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('5.0', '5.0', @fortify_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('4.0', '4.0', @fortify_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('3.0', '3.0', @fortify_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('2.0', '2.0', @fortify_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('1.0', '1.0', @fortify_channel_id);

-- CAT.NET
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('High', 'High', @cat_net_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Medium', 'Medium', @cat_net_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Low', 'Low', @cat_net_channel_id);

-- Checkmarx CxSuite
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Critical', 'Critical', @checkmarx_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Serious', 'Serious', @checkmarx_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Warning', 'Warning', @checkmarx_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Information', 'Information', @checkmarx_channel_id);

-- Find Bugs
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('5', '5', @findbugs_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('4', '4', @findbugs_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('3', '3', @findbugs_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('2', '2', @findbugs_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('1', '1', @findbugs_channel_id);

-- OWASP Orizon
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('High', 'high', @orizon_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Medium', 'medium', @orizon_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Low', 'low', @orizon_channel_id);

-- IBM Rational AppScan Source Edition
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('3', '3', @appscanse_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('2', '2', @appscanse_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('1', '1', @appscanse_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('0', '0', @appscanse_channel_id);

-- IBM Rational AppScan
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('High', 'High', @appscan_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Medium', 'Medium', @appscan_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Low', 'Low', @appscan_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Informational', 'Informational', @appscan_channel_id);

-- Mavituna Security Netsparker
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Critical', 'Critical', @netsparker_net_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Important', 'Important', @netsparker_net_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Medium', 'Medium', @netsparker_net_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Low', 'Low', @netsparker_net_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('Information', 'Information', @netsparker_net_channel_id);

-- WhiteHat Sentinel
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('5', '5', @sentinel_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('4', '4', @sentinel_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('3', '3', @sentinel_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('2', '2', @sentinel_channel_id);
INSERT INTO ChannelSeverity (Name, Code, ChannelTypeId) VALUES ('1', '1', @sentinel_channel_id);



-- INSERT ChannelType SEVERITY MAPPINGS
-- Fortify
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @fortify_channel_id AND Name = 'Hot'), @generic_severity_critical_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @fortify_channel_id AND Name = 'Warning'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @fortify_channel_id AND Name = 'Info'), @generic_severity_info_id);

-- I found these as the Fortify severities - we need to look at more scans to see which ones are used in the general case. - Mac
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @fortify_channel_id AND Name = '5.0'), @generic_severity_critical_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @fortify_channel_id AND Name = '4.0'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @fortify_channel_id AND Name = '3.0'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @fortify_channel_id AND Name = '2.0'), @generic_severity_low_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @fortify_channel_id AND Name = '1.0'), @generic_severity_info_id); 

    
-- CAT.NET
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'High'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Medium'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Low'), @generic_severity_low_id);
    
-- Checkmarx CxSuite
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @checkmarx_channel_id AND Name = 'Critical'), @generic_severity_critical_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @checkmarx_channel_id AND Name = 'Serious'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
	(SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @checkmarx_channel_id AND Name = 'Warning'), @generic_severity_low_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
	(SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @checkmarx_channel_id AND Name = 'Information'), @generic_severity_info_id);
	
-- Find Bugs
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @findbugs_channel_id AND Name = '5'), @generic_severity_critical_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @findbugs_channel_id AND Name = '4'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @findbugs_channel_id AND Name = '3'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @findbugs_channel_id AND Name = '2'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @findbugs_channel_id AND Name = '1'), @generic_severity_low_id);
    
-- OWASP Orizon
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @orizon_channel_id AND Name = 'high'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @orizon_channel_id AND Name = 'medium'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @orizon_channel_id AND Name = 'low'), @generic_severity_low_id);
    
-- IBM Rational AppScan Source Edition
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscanse_channel_id AND Name = '3'), @generic_severity_critical_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscanse_channel_id AND Name = '2'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscanse_channel_id AND Name = '1'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscanse_channel_id AND Name = '0'), @generic_severity_low_id);
    
-- IBM Rational AppScan
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscan_channel_id AND Name = 'High'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Medium'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Low'), @generic_severity_low_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Informational'), @generic_severity_info_id);
    
-- Mavituna Security Netsparker
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Critical'), @generic_severity_critical_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Important'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Medium'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Low'), @generic_severity_low_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Information'), @generic_severity_info_id);

-- WhiteHat Sentinel
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @sentinel_channel_id AND Name = '5'), @generic_severity_critical_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @sentinel_channel_id AND Name = '4'), @generic_severity_high_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @sentinel_channel_id AND Name = '3'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @sentinel_channel_id AND Name = '2'), @generic_severity_medium_id);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (
    (SELECT id FROM ChannelSeverity WHERE ChannelTypeId = @sentinel_channel_id AND Name = '1'), @generic_severity_low_id); 


