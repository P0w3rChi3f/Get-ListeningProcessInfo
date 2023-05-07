# Get-ListeningProcessInfo

Uses NetTCPConnection to get the owiniing processes of network connections.  Take the owning process and usese Win32_Process to get the name of the ProcessID/OwingProcess.  Then Converts the ProcessID to hex and searches the Windows Event Viewer for EventID 4688 and ProcessID. If the record has not been over written it will produce the log information with the network information; this is the default output.  Use the -All if you want output all the listening processes with and without Event logs.

