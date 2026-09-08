event_platform=Win #event_simpleName=ProcessRollup2
| case {
    (ParentBaseFileName=/^(WINWORD|EXCEL|POWERPNT|MSPUB|VISIO|MSACCESS|WINPROJ)\.EXE$/i OR GrandParentBaseFileName=/^(WINWORD|EXCEL|POWERPNT|MSPUB|VISIO|MSACCESS|WINPROJ)\.EXE$/i)
        | ChainRole := "office-descendant"
        | falconPID := TargetProcessId_decimal
        | falconPID := TargetProcessId
        | rename([[FileName, SourceFileName], [CommandLine, SourceCommandLine], [ParentBaseFileName, OfficeParentFileName], [GrandParentBaseFileName, OfficeGrandParentFileName]]);
    *
        | ChainRole := "child"
        | falconPID := ParentProcessId_decimal
        | falconPID := ParentProcessId
        | rename([[FileName, ChildFileName], [CommandLine, ChildCommandLine], [FilePath, ChildFilePath]]);
}
| selfJoinFilter(field=[aid, falconPID], where=[{ChainRole="office-descendant"}, {ChainRole="child"}], prefilter=true)
| groupBy([aid, falconPID], function=[min(ContextTimeStamp, as=FirstSeen), collect([ComputerName, UserName, OfficeParentFileName, OfficeGrandParentFileName, SourceFileName, SourceCommandLine, ChildFilePath, ChildFileName, ChildCommandLine])])
| SourceFileName=* ChildFileName=*
