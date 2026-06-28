# Daily Threat Brief - 2026-06-28

**15 indicators** ingested across 4 sources.
By type: domain=4, ip=4, md5=1, sha256=2, url=4

## Top malware families
- **AgentTesla** - 4 indicators
- **Qakbot** - 3 indicators
- **CobaltStrike** - 3 indicators
- **Lumma** - 3 indicators
- **Emotet** - 2 indicators

## Newest indicators
| first_seen | type | value | malware | source |
|------------|------|-------|---------|--------|
| 2026-06-27 | url | http://45.83.122.10/panel/gate.php | Qakbot | urlhaus |
| 2026-06-27 | url | http://malicious-cdn.test/load.exe | AgentTesla | urlhaus |
| 2026-06-27 | url | http://203.0.113.9/beacon | CobaltStrike | urlhaus |
| 2026-06-27 | url | http://lure.test/invoice.html | AgentTesla | urlhaus |
| 2026-06-27 | domain | c2.evil-domain.test | CobaltStrike | otx |
| 2026-06-27 | ip | 185.220.101.50 | CobaltStrike | feodo |
| 2026-06-27 | ip | 45.83.122.10 | Qakbot | feodo |
| 2026-06-27 | ip | 91.92.240.5 | Lumma | feodo |
| 2026-06-27 | sha256 | 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f | AgentTesla | malwarebazaar |
| 2026-06-26 | domain | update-check.evil.test | Lumma | otx |

> Tip: pipe the indicator values through `iocsift` to enrich/refang them, and feed the C2 IPs into the detection pipeline (project 07).
