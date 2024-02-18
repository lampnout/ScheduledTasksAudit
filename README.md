# ScheduledTasksAudit

This short project is intended to automate the identification of privilege escalation vectors in scheduled tasks by investigating the *Actions* item(s) of each scheduled task.

The project was initialy created as a [Seatbelt](https://github.com/GhostPack/Seatbelt) module in this [pull request](https://github.com/GhostPack/Seatbelt/pull/126).

This *README.md* is divided in the following sections:

- [Approach](#approach)
- [Output](#output)
- [Support and Issues](#support-and-issues)

## Approach

The code applies filtering to skip the investigation of:

- disabled scheduled tasks
- scheduled tasks that run under the context of the user account that makes the audit
- scheduled tasks that do not *start a program* and instead run something like a *custom handler*

After applying the filters, the *Actions* item(s) of each task are collected and assembled with the purpose of identifying what files (executables or scripts) a task runs.

Each identified file is checked to first determine if indeed exists on the host. If so, the permissions of the file are checked to identify if the user account that performs the check can replace the file or - in the case of a script - append data at the end.

The endgame is to identify a) scheduled tasks that run under the context of a different user account and b) if the user account who performs the audit has the relevant permissions that would allow them control the files the scheduled task runs.

## Output

If scheduled tasks with configuration that could allow exploitation for privilege escalation are identified, the output will look like the following:

```
[+] ScheduledTasksAudit start:
  Name                               :   SampleTask1
  Task Path                          :   \
  UserId (Runs as)                   :   SYSTEM
  State                              :   Ready
  Execution Action                   :   C:\Users\TestUser1\does\not\exist\hello.exe
    Execute Property                 :   C:\Users\TestUser1\does\not\exist\hello.exe
    Investigate Permissions of file  :   C:\Users\TestUser1\does\not\exist\hello.exe
    Suspicious Permissions           :
    Finding Description              :   Directory and file do not exist

  Name                               :   SampleTask2
  Task Path                          :   \
  UserId (Runs as)                   :   SYSTEM
  State                              :   Ready
  Execution Action                   :   C:\Users\TestUser2\AppData\Roaming\adnetwork1.exe
    Execute Property                 :   %APPDATA%\adnetwork1.exe
    Investigate Permissions of file  :   C:\Users\TestUser2\AppData\Roaming\adnetwork1.exe
    Suspicious Permissions           :
    Finding Description              :   File does not exist

  Name                               :   SampleTask3
  Task Path                          :   \
  UserId (Runs as)                   :   SYSTEM
  State                              :   Ready
  Execution Action                   :   C:\Users\TestUser1\network\listcomputers.exe --first-arg --second-arg
    Execute Property                 :   C:\Users\TestUser1\network\listcomputers.exe
    Investigate Permissions of file  :   C:\Users\TestUser1\network\listcomputers.exe
    Suspicious Permissions           :
              DESKTOP-123456\TestUser1 - Write, ReadAndExecute, Synchronize
              DESKTOP-123456\TestUser2 - Write, FullControl
    Finding Description              :   File permissions

[+] ScheduledTasksAudit end
```

## Support and Issues

Please use [issues](https://github.com/lampnout/ScheduledTasksAudit/issues) for any feedback.
