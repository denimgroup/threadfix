-- add entries for Riverbed WAF (SteelApp Web App Firewall)
INSERT INTO WAFTYPE (initialid, name) VALUES (100000, 'SteelApp Web App Firewall');
INSERT INTO WAFRULEDIRECTIVE (directive, waftypeid) VALUES ('deny', (SELECT id FROM WAFTYPE WHERE name = 'SteelApp Web App Firewall'));

