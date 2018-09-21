CREATE TABLE `AccessControlApplicationMap` (`id` INT AUTO_INCREMENT NOT NULL, `active` TINYINT(1) NOT NULL, `createdDate` DATETIME NOT NULL, `modifiedDate` DATETIME NOT NULL, `accessControlTeamMapId` INT NOT NULL, `applicationId` INT NOT NULL, `roleId` INT NULL, CONSTRAINT `SYS_PK_101` PRIMARY KEY (`id`));
CREATE TABLE `AccessControlTeamMap` (`id` INT AUTO_INCREMENT NOT NULL, `active` TINYINT(1) NOT NULL, `createdDate` DATETIME NOT NULL, `modifiedDate` DATETIME NOT NULL, `allApps` TINYINT(1) NULL, `organizationId` INT NOT NULL, `roleId` INT NULL, `userId` INT NOT NULL, CONSTRAINT `SYS_PK_72` PRIMARY KEY (`id`));
CREATE TABLE `DefaultConfiguration` (`id` INT AUTO_INCREMENT NOT NULL, `defaultRoleId` INT NULL, `globalGroupEnabled` TINYINT(1) NULL, CONSTRAINT `SYS_PK_74` PRIMARY KEY (`id`));
CREATE TABLE `VulnerabilityComment` (`id` INT AUTO_INCREMENT NOT NULL, `active` TINYINT(1) NOT NULL, `createdDate` DATETIME NOT NULL, `modifiedDate` DATETIME NOT NULL, `comment` VARCHAR(200) NULL, `time` DATETIME NULL, `userId` INT NULL, `vulnerabilityId` INT NULL, CONSTRAINT `SYS_PK_224` PRIMARY KEY (`id`));
ALTER TABLE `APIKey` ADD `active` TINYINT(1) NOT NULL;
ALTER TABLE `APIKey` ADD `createdDate` DATETIME NOT NULL;
ALTER TABLE `APIKey` ADD `modifiedDate` DATETIME NOT NULL;
ALTER TABLE `RemoteProviderApplication` ADD `active` TINYINT(1) NOT NULL;
ALTER TABLE `RemoteProviderApplication` ADD `createdDate` DATETIME NOT NULL;
ALTER TABLE `RemoteProviderApplication` ADD `modifiedDate` DATETIME NOT NULL;
ALTER TABLE `Role` ADD `active` TINYINT(1) NOT NULL DEFAULT '1';
ALTER TABLE `Role` ADD `canGenerateReports` TINYINT(1);
ALTER TABLE `Role` ADD `canGenerateWafRules` TINYINT(1);
ALTER TABLE `Role` ADD `canManageAPIKeys` TINYINT(1);
ALTER TABLE `Role` ADD `canManageAPPLICATIONS` TINYINT(1);
ALTER TABLE `Role` ADD `canManageDEFECTTRACKERS` TINYINT(1);
ALTER TABLE `Role` ADD `canManageREMOTEPROVIDERS` TINYINT(1);
ALTER TABLE `Role` ADD `canManageRoles` TINYINT(1);
ALTER TABLE `Role` ADD `canManageTEAMS` TINYINT(1);
ALTER TABLE `Role` ADD `canManageUSERS` TINYINT(1);
ALTER TABLE `Role` ADD `canManageWAFS` TINYINT(1);
ALTER TABLE `Role` ADD `canModifyVulnerabilities` TINYINT(1);
ALTER TABLE `Role` ADD `canSubmitDefects` TINYINT(1);
ALTER TABLE `Role` ADD `canUploadScans` TINYINT(1);
ALTER TABLE `Role` ADD `canViewErrorLogs` TINYINT(1);
ALTER TABLE `Role` ADD `canViewJobStatuses` TINYINT(1);
ALTER TABLE `Role` ADD `createdDate` DATETIME NOT NULL;
ALTER TABLE `Role` ADD `modifiedDate` DATETIME NOT NULL;
ALTER TABLE `User` ADD `hasGlobalGroupAccess` TINYINT(1);
ALTER TABLE `User` MODIFY `RoleId` INT NULL;
ALTER TABLE `AccessControlApplicationMap` ADD CONSTRAINT `FKD8CDF9855AD99D46` FOREIGN KEY (`AccessControlTeamMapId`) REFERENCES `AccessControlTeamMap` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `AccessControlApplicationMap` ADD CONSTRAINT `FKD8CDF985C96E039C` FOREIGN KEY (`applicationId`) REFERENCES `Application` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `AccessControlApplicationMap` ADD CONSTRAINT `FKD8CDF985D03E73C6` FOREIGN KEY (`roleId`) REFERENCES `Role` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `AccessControlTeamMap` ADD CONSTRAINT `FK2321484688316300` FOREIGN KEY (`organizationId`) REFERENCES `Organization` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `AccessControlTeamMap` ADD CONSTRAINT `FK23214846D03E73C6` FOREIGN KEY (`roleId`) REFERENCES `Role` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `AccessControlTeamMap` ADD CONSTRAINT `FK23214846D593C930` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `VulnerabilityComment` ADD CONSTRAINT `FK59FFE263D593C930` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `VulnerabilityComment` ADD CONSTRAINT `FK59FFE263DFCC92B4` FOREIGN KEY (`vulnerabilityId`) REFERENCES `Vulnerability` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `Role` DROP COLUMN `name`;
INSERT INTO ChannelType (name, url, version, exportInfo) VALUES ('NTO Spider', 'http://www.ntobjectives.com/security-software/ntospider-application-security-scanner/', '5.4', 'ThreadFix imports the VulnerabilitiesSummary generated in the Reports/scan-name/date directory after the scan finishes.');
INSERT INTO DefectTrackerType (name,fullClassName) VALUES ('Microsoft TFS', 'com.denimgroup.threadfix.service.defects.TFSDefectTracker');
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Active Content Analysis', 'Active Content Analysis', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Active-X Control Attacking', 'Active-X Control Attacking', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Arbitrary File Upload', 'Arbitrary File Upload', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Authentication Form SQL Injection', 'Authentication Form SQL Injection', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Authentication Testing', 'Authentication Testing', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Blind SQL', 'Blind SQL', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Compliance', 'Compliance', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Cookie Analysis', 'Cookie Analysis', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Cross-Site Scripting', 'Cross-Site Scripting', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Cross-Site Tracing', 'Cross-Site Tracing', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Directory Indexing', 'Directory Indexing', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Financial Compliance', 'Financial Compliance', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Frame/iFrame Content Analysis', 'Frame/iFrame Content Analysis', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('HTTP Response Splitting', 'HTTP Response Splitting', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Java Grinder', 'Java Grinder', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('OS Commanding', 'OS Commanding', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Parameter Analysis', 'Parameter Analysis', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Predictable Resource Location', 'Predictable Resource Location', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Reflection Analysis', 'Reflection Analysis', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Remote File Include', 'Remote File Include', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Reverse Proxy', 'Reverse Proxy', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('SQL Injection', 'SQL Injection', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('SSL Strength Analysis', 'SSL Strength Analysis', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Server Configuration', 'Server Configuration', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Session Strength Analysis', 'Session Strength Analysis', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Source Code Disclosure', 'Source Code Disclosure', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Web Beacon', 'Web Beacon', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Web Service (SOAP) Analysis', 'Web Service (SOAP) Analysis', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Arachni') AND code = 'A backup file exists on the server.'), (SELECT id FROM GenericVulnerability WHERE name = 'Exposure of Backup File to an Unauthorized Control Sphere'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Arachni') AND code = 'A common sensitive file exists on the server.'), (SELECT id FROM GenericVulnerability WHERE name = 'Information Exposure'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Arachni') AND code = 'Misconfiguration in LIMIT directive of .htaccess file.'), (SELECT id FROM GenericVulnerability WHERE name = 'Trusting HTTP Permission Methods on the Server Side'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Arachni') AND code = 'WebDAV'), (SELECT id FROM GenericVulnerability WHERE name = 'Uncontrolled Search Path Element'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Authentication Form SQL Injection'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Authentication'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Authentication Testing'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Authentication'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Blind SQL'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Compliance'), (SELECT id FROM GenericVulnerability WHERE name = 'Privacy Violation'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Cross-Site Scripting'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Cross-Site Tracing'), (SELECT id FROM GenericVulnerability WHERE name = 'Information Exposure Through Debug Information'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Directory Indexing'), (SELECT id FROM GenericVulnerability WHERE name = 'Information Exposure Through Directory Listing'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'OS Commanding'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Neutralization of Special Elements used in an OS Command (''OS Command Injection'')'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Parameter Analysis'), (SELECT id FROM GenericVulnerability WHERE name = 'Information Exposure Through an Error Message'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Predictable Resource Location'), (SELECT id FROM GenericVulnerability WHERE name = 'Exposure of Backup File to an Unauthorized Control Sphere'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Remote File Include'), (SELECT id FROM GenericVulnerability WHERE name = 'Exposure of Backup File to an Unauthorized Control Sphere'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Remote File Include'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'SQL Injection'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Server Configuration'), (SELECT id FROM GenericVulnerability WHERE name = 'Information Exposure Through Environmental Variables'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Session Strength Analysis'), (SELECT id FROM GenericVulnerability WHERE name = 'Use of Insufficiently Random Values'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Arbitrary File Upload'), (SELECT id FROM GenericVulnerability WHERE name = 'Unrestricted Upload of File with Dangerous Type'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'HTTP Response Splitting'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Neutralization of CRLF Sequences in HTTP Headers (''HTTP Response Splitting'')'));
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = 'Source Code Disclosure'), (SELECT id FROM GenericVulnerability WHERE name = 'Information Exposure Through Source Code'));
INSERT INTO ChannelSeverity (name, code, channelTypeId, numericValue) VALUES ('0-Safe', '0-Safe', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'), 1);
INSERT INTO ChannelSeverity (name, code, channelTypeId, numericValue) VALUES ('1-Info', '1-Info', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'), 2);
INSERT INTO ChannelSeverity (name, code, channelTypeId, numericValue) VALUES ('2-Low', '2-Low', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'), 3);
INSERT INTO ChannelSeverity (name, code, channelTypeId, numericValue) VALUES ('3-Med', '3-Med', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'), 4);
INSERT INTO ChannelSeverity (name, code, channelTypeId, numericValue) VALUES ('4-High', '4-High', (SELECT id FROM ChannelType WHERE name = 'NTO Spider'), 5);
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES ((SELECT id FROM ChannelSeverity WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = '4-High'), (SELECT id FROM GenericSeverity WHERE name = 'Critical'));
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES ((SELECT id FROM ChannelSeverity WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = '3-Med'), (SELECT id FROM GenericSeverity WHERE name = 'High'));
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES ((SELECT id FROM ChannelSeverity WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = '2-Low'), (SELECT id FROM GenericSeverity WHERE name = 'Medium'));
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES ((SELECT id FROM ChannelSeverity WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = '1-Info'), (SELECT id FROM GenericSeverity WHERE name = 'Low'));
INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES ((SELECT id FROM ChannelSeverity WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'NTO Spider') AND code = '0-Safe'), (SELECT id FROM GenericSeverity WHERE name = 'Info'));
UPDATE Role SET createdDate=NOW(), modifiedDate=NOW(), active=1,canGenerateReports=1,canGenerateWafRules=1,canManageApiKeys=1,canManageApplications=1,canManageDefectTrackers=1,canManageRemoteProviders=1,canManageRoles=1,canManageTeams=1,canManageUsers=1,canManageWafs=1,canModifyVulnerabilities=1,canSubmitDefects=1,canUploadScans=1,canViewErrorLogs=1,canViewJobStatuses=1 WHERE displayname = 'Administrator';
UPDATE Role SET createdDate=NOW(), modifiedDate=NOW(), active=1,canGenerateReports=0,canGenerateWafRules=0,canManageApiKeys=0,canManageApplications=0,canManageDefectTrackers=0,canManageRemoteProviders=0,canManageRoles=0,canManageTeams=0,canManageUsers=0,canManageWafs=0,canModifyVulnerabilities=0,canSubmitDefects=0,canUploadScans=0,canViewErrorLogs=0,canViewJobStatuses=0 WHERE displayname = 'User';
UPDATE User SET HASGLOBALGROUPACCESS=1;
UPDATE RemoteProviderApplication SET createdDate=NOW(), modifiedDate=NOW(), active=1;
UPDATE APIKey SET createdDate=NOW(), modifiedDate=NOW(), active=1;