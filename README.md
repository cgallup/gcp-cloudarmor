# Cloud Armor Project

The Cloud Armor project is for the Google Cloud Platform Web Application Firewall "Cloud Armor".
The security policy can not duplicate a backend target, that another target is using.

Ofac is the security policy that has 1 geo-blocking rule, and 10 OWASP rules, pointing to a single kubernettes backend target, Default kubernetes L7 Load balancing health check.
