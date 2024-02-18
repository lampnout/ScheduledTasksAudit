using System;
using System.Management;
using System.Linq;
using System.Security.Principal;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.IO;
using System.Security.AccessControl;

namespace ScheduledTaskAudit
{
    enum StateEnum
    {
        Unknown = 0,
        Disabled = 1,
        Queued = 2,
        Ready = 3,
        Running = 4
    };
    
    internal class ScheduledTaskAudit
    {
        public static void CollectScheduledTaskActions(ManagementBaseObject[] actions, ref List<Dictionary<string, object>> ActionsList)
        {
            foreach (var obj in actions)
            {
                // action of a task - full arguments                    
                var TaskProperties = new Dictionary<string, object>();

                foreach (var prop in obj.Properties)
                {
                    if (!prop.Name.Equals("PSComputerName"))
                    {
                        TaskProperties[prop.Name] = prop.Value;
                    }
                }

                // filter out tasks with no "Execute" key
                if (!TaskProperties.ContainsKey("Execute")) { continue; }

                // Execute action contains .cmd/.bat/.vbs/.js
                var ActionCompact = "";
                var tempDict = new Dictionary<string, object>();
                if (Regex.IsMatch(TaskProperties["Execute"].ToString().ToLower(), @"\.(cmd|bat|vbs|js)$"))
                {
                    ActionCompact = Environment.ExpandEnvironmentVariables(TaskProperties["Execute"].ToString());
                    string ExecInvestigate = ActionCompact;
                    if (Regex.IsMatch(ActionCompact, @"\\"))
                    {
                        ActionCompact = ActionCompact + " " + TaskProperties["Arguments"]?.ToString();
                    }
                    else
                    {
                        if (!(TaskProperties["WorkingDirectory"] is null))
                        {
                            ExecInvestigate = TaskProperties["WorkingDirectory"]?.ToString() + ActionCompact;
                            ActionCompact = ExecInvestigate + " " + TaskProperties["Arguments"]?.ToString();
                        }
                    }
                    tempDict.Add("Execute Investigate", ExecInvestigate);
                }
                else if (Regex.IsMatch(TaskProperties["Execute"].ToString().ToLower(), @"\.exe$"))
                {
                    ActionCompact = TaskProperties["Execute"].ToString();
                    // path includes environment variable - needs expansion
                    if (Regex.IsMatch(ActionCompact, @"%\\"))
                    {
                        ActionCompact = Environment.ExpandEnvironmentVariables(ActionCompact);
                    }
                    tempDict.Add("Execute Investigate", ActionCompact);
                    if (!(TaskProperties["Arguments"]?.ToString() is null))
                    {
                        if (Regex.IsMatch(TaskProperties["Arguments"]?.ToString().ToLower(), @"\.(cmd|bat|vbs|js|ps1)$"))
                        {
                            tempDict["Execute Investigate"] = TaskProperties["Arguments"].ToString();
                        }
                    }
                    ActionCompact = ActionCompact + " " + TaskProperties["Arguments"]?.ToString();
                }

                tempDict.Add("CompleteArguments", ActionCompact);
                tempDict.Add("ExecProp", TaskProperties["Execute"].ToString());
                ActionsList.Add(tempDict);
            }
        }

        public static bool dirPermissionsCheck(Dictionary<string, object> action, string idref, string ipath)
        {
            FileSecurity dir_acl = File.GetAccessControl(Path.GetDirectoryName(action["Execute Investigate"].ToString()));
            AuthorizationRuleCollection dirAccessRules = dir_acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
            foreach (FileSystemAccessRule dirAccessRule in dirAccessRules)
            {
                if (!dirAccessRule.IdentityReference.Value.Equals(idref)) { continue; }
                if (Regex.IsMatch(dirAccessRule.FileSystemRights.ToString(), @"FullControl|Modify|Write|ReadAndExecute"))
                {
                    return true;
                }
            }
            return false;
        }

        public static void PermissionsCheck(ref Dictionary<string, object> perm, FileSystemRights accessright, string user, string accessrule)
        {
            if (perm.ContainsKey(user))
            {
                // if permission is not in the value, add it
                if (!Regex.IsMatch(perm[user].ToString(), accessright.ToString()))
                {
                    string[] array = { accessright.ToString(), (string)perm[user] };
                    perm[user] = string.Join(", ", array);
                }
            }
            else
            {
                perm.Add(user, accessrule);
            }
        }

        public static void TaskActionIteration(ref List<Dictionary<string, object>> ActionsList)
        {
            foreach (var action in ActionsList)
            {
                // iterate the system path and construct the filepath
                if (!Regex.IsMatch(action["Execute Investigate"].ToString().ToLower(), @"\\"))
                {
                    if (Regex.IsMatch(action["Execute Investigate"].ToString().ToLower(), @"\.exe$"))
                    {
                        var syspath = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine).Split(';');
                        foreach (string path in syspath)
                        {
                            if (path == "") { continue; }
                            if (File.Exists(path + @"\" + action["Execute Investigate"].ToString()))
                            {
                                action["Execute Investigate"] = path + @"\" + action["Execute Investigate"].ToString();
                                break;
                            }
                        }
                    }
                }

                var perm = new Dictionary<string, object>();
                // file does not exist
                if (!File.Exists(action["Execute Investigate"].ToString()))
                {
                    action.Add("VectorDescr", "N/A");
                    var fpath = action["Execute Investigate"].ToString();
                    action["VectorDescr"] = "File does not exist";
                    if ((Path.GetDirectoryName(fpath) != "") && (!Directory.Exists(Path.GetDirectoryName(fpath))))
                    {
                        action["VectorDescr"] = "Directory and file do not exist";
                    }
                    action["Permissions"] = perm;
                    continue;
                }

                // check file permissions - last stage of this module
                FileSecurity file_acl = File.GetAccessControl(action["Execute Investigate"].ToString());
                AuthorizationRuleCollection AccessRules = file_acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));

                foreach (FileSystemAccessRule rule in AccessRules)
                {
                    try
                    {
                        if (Regex.IsMatch(rule.IdentityReference.Translate(typeof(NTAccount)).Value.ToUpper(), @"SYSTEM|Administrators|TrustedInstaller".ToUpper()))
                        {
                            continue;
                        }

                        if (!dirPermissionsCheck(action, rule.IdentityReference.Value, action["Execute Investigate"].ToString()))
                        {
                            continue;
                        }

                        var username = rule.IdentityReference.Translate(typeof(NTAccount)).Value;
                        var accessrule = rule.FileSystemRights.ToString();

                        if ((FileSystemRights.FullControl & rule.FileSystemRights) == FileSystemRights.FullControl)
                        {
                            // this needs to be a function
                            var accessright = FileSystemRights.FullControl;
                            PermissionsCheck(ref perm, accessright, username, accessrule);
                            if (!action.ContainsKey("VectorDescr"))
                            {
                                action.Add("VectorDescr", "File permissions");
                            }
                        }
                        if ((FileSystemRights.Write & rule.FileSystemRights) == FileSystemRights.Write)
                        {
                            var accessright = FileSystemRights.Write;
                            PermissionsCheck(ref perm, accessright, username, accessrule);
                            if (!action.ContainsKey("VectorDescr"))
                            {
                                action.Add("VectorDescr", "File permissions");
                            }
                        }
                        if ((FileSystemRights.AppendData & rule.FileSystemRights) == FileSystemRights.AppendData)
                        {
                            // check the append permissions to append data in scripts
                            if (Regex.IsMatch(action["Execute Investigate"].ToString().ToLower(), @"\.(cmd|bat|vbs|js|ps1)$"))
                            {
                                var accessright = FileSystemRights.AppendData;
                                PermissionsCheck(ref perm, accessright, username, accessrule);
                                if (!action.ContainsKey("VectorDescr"))
                                {
                                    action.Add("VectorDescr", "File permissions");
                                }
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
                if (perm.Count > 0)
                {
                    action["Permissions"] = perm;
                }
            }
        }

        public struct TaskFinding
        {
            public string TaskName;
            public string TaskPath;
            public StateEnum TaskState;
            public string TaskUserID;
            public List<Dictionary<string, object>> TaskActionList;
        }
        public static void FormatOutput(TaskFinding finding)
        {
            Console.WriteLine("  {0,-30}     :   {1}", "Name", finding.TaskName);
            Console.WriteLine("  {0,-30}     :   {1}", "Task Path", finding.TaskPath);
            Console.WriteLine("  {0,-30}     :   {1}", "UserId (Runs as)", finding.TaskUserID);
            Console.WriteLine("  {0,-30}     :   {1}", "State", finding.TaskState);
            foreach (var action in finding.TaskActionList)
            {
                Console.WriteLine("  {0,-30}     :   {1}", "Execution Action", action["CompleteArguments"]);
                Console.WriteLine("    {0,-30}   :   {1}", "Execute Property", action["ExecProp"]);
                Console.WriteLine("    {0,-30}  :   {1}", "Investigate Permissions of file", action["Execute Investigate"]);
                if (action.ContainsKey("Permissions"))
                {
                    Console.WriteLine("    {0,-30}   :", "Suspicious Permissions");
                    foreach (var kvp in (Dictionary<string, object>)action["Permissions"])
                    {
                        if (!String.IsNullOrEmpty($"{kvp.Value}"))
                        {
                            Console.WriteLine("        {0,30} - {1}", kvp.Key, kvp.Value);
                        }
                    }
                }
                Console.WriteLine("    {0,-30}   :   {1}", "Finding Description", action["VectorDescr"]);
            }
            Console.WriteLine();
        }

        static int Main()
        {
            ManagementObjectCollection task_objects = null;
            try
            {
                // perform the WMI query to collect scheduled tasks
                ManagementScope mScope = new ManagementScope(@"ROOT\Microsoft\Windows\TaskScheduler");
                SelectQuery wmiQuery = new SelectQuery("SELECT * FROM MSFT_ScheduledTask");
                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(mScope, wmiQuery);
                task_objects = wmiData.Get();                
            }
            catch
            {
                Console.WriteLine("[-] WMI error");
            }

            if (task_objects == null) { return 1; }

            Console.WriteLine("[+] ScheduledTasksAudit start:");
            // iterate on task objects
            foreach (var task in task_objects)
            {
                var result = (ManagementObject)task;
                var tempPrincipal = (ManagementBaseObject)result["Principal"];
                var actions = (ManagementBaseObject[])result["Actions"];

                // if module runs from an elevated user context exit
                string[] privs = { "SYSTEM", "LOCAL SERVICE" };
                if (privs.Contains(Environment.UserName.ToUpper()))
                {
                    Console.WriteLine("[X] You are running this module with elevated permissions. You need to run it under the context of a low-privileged user account.");
                    break;
                }

                var userid = tempPrincipal["UserId"]?.ToString();
                // filter out scheduled tasks that meet the following requirements:
                // do not run as the current user OR when the field "when running, use the following user account" is empty
                // AND are disabled
                if (((userid?.ToUpper() == Environment.UserName.ToUpper()) ||
                     (String.IsNullOrEmpty(userid))) ||
                     ((int)result["State"] == (int)StateEnum.Disabled))
                {
                    continue;
                }

                var ActionsList = new List<Dictionary<string, object>>();
                CollectScheduledTaskActions(actions, ref ActionsList);

                // don't include findings in the output
                if (ActionsList.Count < 1) { continue; };

                // action iterate - checks file permissions of each action
                TaskActionIteration(ref ActionsList);

                // filter out - don't print Actions with less than 5 members
                // A task action should have the keys: "Execute Investigate", "CompleteArguments", "ExecProperty", "VectorDescr" and "Permissions"
                var flag = false;
                foreach (var action in ActionsList)
                {
                    if (action.Count < 5)
                    {
                        flag = true;
                    }
                }
                if (flag) { continue; }

                var finding = new TaskFinding()
                {
                    TaskName = result["TaskName"].ToString(),
                    TaskPath = result["TaskPath"].ToString(),
                    TaskState = (StateEnum)result["State"],
                    TaskUserID = userid,
                    TaskActionList = ActionsList
                };
                
                FormatOutput(finding);
            }
            Console.WriteLine("[+] ScheduledTasksAudit end");

            task_objects.Dispose();
                       
            return 0;
        }
    }
}
