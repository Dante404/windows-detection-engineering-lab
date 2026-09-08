event_platform=Win #event_simpleName=/^(BitsJobCreated|ProcessRollup2|NetworkConnectIP4|CustomIOADomainNameDetectionInfoEvent)$/
| falconPID := TargetProcessId_decimal
| falconPID := TargetProcessId
| falconPID := ContextProcessId
| ResolvedDomain := IOCValue
| ResolvedDomain := DnsRequest
| ResolvedDomain := HttpRequestURL
| ResolvedDomain := URL
| ResolvedDomain := DomainName
| default(field=[TargetFileName, ResolvedDomain], value="")
| TargetFileName!=/(\.tmp$|\\Temp\\|\\Google\\Chrome\\|\\Microsoft\\Edge\\|\\CCM\\|\\Outlook\\|\\Adobe\\)/i
| ResolvedDomain!=/(\.svc\.cloud\.microsoft$|(^|\.)globalcdn\.co$|(^|\.)tm-azurefd\.net$)/i
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=BitsJobCreated}, {#event_simpleName=ProcessRollup2}], prefilter=true)
| groupBy([aid, falconPID], function=[min(ContextTimeStamp, as=FirstSeen), count(as=EventCount), collect([TargetFileName, ResolvedDomain, RemoteAddressIP4, ImageFileName, CommandLine, ComputerName, UserName])])
| TargetFileName=* ImageFileName=*
