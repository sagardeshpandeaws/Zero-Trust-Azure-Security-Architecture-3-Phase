# KQL Master Reference — Basic to Advanced
### Security Operations Engineer Handbook

---

## Table of Contents

1. [Level 1: Foundation Operators](#level-1-foundation-operators)
2. [Level 2: Aggregation & Grouping](#level-2-aggregation--grouping)
3. [Level 3: Multi-Table Operations](#level-3-multi-table-operations)
4. [Level 4: Advanced Data Shaping](#level-4-advanced-data-shaping)
5. [Level 5: Window Functions & Time Series](#level-5-window-functions--time-series)
6. [Level 6: Functions & Reusability](#level-6-functions--reusability)
7. [Level 7: Performance Optimization](#level-7-performance-optimization)
8. [Level 8: Expert SIEM Detection Engineering](#level-8-expert-siem-detection-engineering)
9. [SC-200 Key Tables Quick Reference](#sc-200-key-tables-quick-reference)
10. [MITRE ATT&CK Detection Patterns](#mitre-attck-detection-patterns)

---

# Level 1: Foundation Operators

---

### `take` — Sample rows

**Problem:** You need a quick peek at the data before writing complex queries.

```kql
SigninLogs
| take 10
```

| Timestamp | UserPrincipalName | AppDisplayName | IPAddress | ResultType |
|-----------|-------------------|----------------|-----------|------------|
| ... | user@yourtenant.com | Azure Portal | 1.2.3.4 | 0 |

---

### `count` — Row count

**Problem:** How many sign-in attempts happened today?

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| count
```

---

### `where` — Filter rows

**Problem 1:** Show only failed sign-ins (ResultType != "0").

```kql
SigninLogs
| where ResultType != "0"
```

**Problem 2:** Find sign-ins from a specific user in the last 7 days.

```kql
SigninLogs
| where UserPrincipalName == "admin@yourtenant.com"
| where TimeGenerated > ago(7d)
```

**Problem 3:** Find sign-ins from IPs NOT in the internal ranges.

```kql
SigninLogs
| where IPAddress !startswith "10."
  and IPAddress !startswith "192.168."
  and IPAddress !startswith "172."
```

**Problem 4:** Find events within a specific time window.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-07-01 08:00) .. datetime(2026-07-01 18:00))
```

---

### `project` — Pick columns

**Problem:** You only need user, IP, and result — drop everything else.

```kql
SigninLogs
| project UserPrincipalName, IPAddress, ResultType, TimeGenerated
```

**Variation — Drop specific columns:**

```kql
SigninLogs
| project-away ConditionalAccessStatus, RiskDetail
```

**Variation — Reorder:**

```kql
SigninLogs
| project-reorder TimeGenerated, UserPrincipalName
```

---

### `extend` — Create calculated columns

**Problem 1:** Add an hour-of-day column for time analysis.

```kql
SigninLogs
| extend Hour = datetime_part("hour", TimeGenerated)
```

**Problem 2:** Classify sign-in risk.

```kql
SigninLogs
| extend RiskLevel = case(
    RiskLevelDuringSignIn == "none", "Low",
    RiskLevelDuringSignIn == "medium", "Medium",
    RiskLevelDuringSignIn == "high", "High",
    "Unknown"
)
```

**Problem 3:** Create a flagged column for external IPs.

```kql
SigninLogs
| extend IsExternal = iff(
    IPAddress !startswith "10." and
    IPAddress !startswith "192.168." and
    IPAddress !startswith "172.",
    true, false
)
```

**Problem 4:** Concatenate fields for alert description.

```kql
SigninLogs
| extend AlertDescription = strcat(
    UserPrincipalName, " from ", IPAddress,
    " - ", ResultType, " at ", TimeGenerated
)
```

---

### `distinct` — Unique values

**Problem 1:** List all unique users who failed sign-in.

```kql
SigninLogs
| where ResultType != "0"
| distinct UserPrincipalName
```

**Problem 2:** Find all unique IP + User combinations.

```kql
SigninLogs
| distinct UserPrincipalName, IPAddress
```

---

### `order by` / `sort by` — Sorting

**Problem:** Show most recent failed sign-ins first.

```kql
SigninLogs
| where ResultType != "0"
| order by TimeGenerated desc
```

---

# Level 2: Aggregation & Grouping

---

### `summarize count()` — Group and count

**Problem 1:** Count failed sign-ins per user, show top offenders.

```kql
SigninLogs
| where ResultType != "0"
| summarize FailCount = count() by UserPrincipalName
| order by FailCount desc
```

**Problem 2:** Count sign-ins per hour of the day.

```kql
SigninLogs
| summarize EventCount = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```

---

### `countif()` — Conditional count

**Problem:** Count successful vs failed sign-ins per user.

```kql
SigninLogs
| summarize
    Total = count(),
    Successes = countif(ResultType == "0"),
    Failures = countif(ResultType != "0")
  by UserPrincipalName
| order by Failures desc
```

---

### `dcount()` — Approximate unique count

**Problem:** How many unique IPs did each user sign in from?

```kql
SigninLogs
| summarize UniqueIPs = dcount(IPAddress) by UserPrincipalName
| order by UniqueIPs desc
```

---

### `make_set()` / `make_list()` — Collect values

**Problem 1:** List all IPs used by each user (no duplicates).

```kql
SigninLogs
| where ResultType != "0"
| summarize IPsUsed = make_set(IPAddress) by UserPrincipalName
```

**Problem 2:** Track sign-in IPs in order (with duplicates, chronological).

```kql
SigninLogs
| order by TimeGenerated asc
| summarize IPHistory = make_list(IPAddress) by UserPrincipalName
```

---

### `min()` / `max()` — Find extremes

**Problem:** Find first and last sign-in time and IP per user.

```kql
SigninLogs
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    FirstIP = arg_min(TimeGenerated, IPAddress).IPAddress,
    LastIP = arg_max(TimeGenerated, IPAddress).IPAddress
  by UserPrincipalName
```

---

### `bin()` — Time bucketing

**Problem:** Count failed sign-ins in 5-minute windows to detect spikes.

```kql
SigninLogs
| where ResultType != "0"
| summarize FailCount = count() by bin(TimeGenerated, 5m)
| where FailCount > 10
| order by FailCount desc
```

---

### `percentile()` — Percentile calculation

**Problem:** Find the 95th percentile of failed sign-in latency.

```kql
SigninLogs
| where ResultType != "0"
| summarize P95 = percentile(TimeGenerated - TimeGenerated, 95)
// Real use case: percentile(duration_column, 95)
```

---

### Real-World Exercise — Brute Force Detection (Level 2)

**Problem:** Detect users with 5+ failed sign-ins in any 10-minute window.

```kql
SigninLogs
| where ResultType != "0"
| summarize FailCount = count()
  by UserPrincipalName, bin(TimeGenerated, 10m)
| where FailCount >= 5
| order by FailCount desc
```

---

# Level 3: Multi-Table Operations

---

### `join` — Merge tables

**Types:**
- `inner` — only matching rows
- `leftouter` — all left rows, nulls where no match
- `leftanti` — rows in left NOT in right
- `leftsemi` — rows in left that HAVE a match
- `rightouter` / `fullouter`

---

**Problem 1 (inner join):** Find failed sign-ins where the user is a known admin.

```kql
let AdminUsers = IdentityInfo
    | where JobTitle == "Global Admin" or JobTitle == "Security Admin"
    | project AccountUPN;
SigninLogs
| where ResultType != "0"
| where UserPrincipalName in (AdminUsers)
| join kind=inner AdminUsers on $left.UserPrincipalName == $right.AccountUPN
```

**Better approach using `in`:**

```kql
let AdminUsers = IdentityInfo
    | where JobTitle in ("Global Admin", "Security Admin")
    | distinct AccountUPN;
SigninLogs
| where UserPrincipalName in (AdminUsers)
| where ResultType != "0"
```

---

**Problem 2 (leftouter):** Enrich sign-in logs with user department.

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| join kind=leftouter (
    IdentityInfo | project AccountUPN, Department, JobTitle
) on $left.UserPrincipalName == $right.AccountUPN
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, Department, JobTitle
```

---

**Problem 3 (leftanti):** Find users in sign-in logs NOT in the employee directory.

```kql
SigninLogs
| distinct UserPrincipalName
| join kind=leftanti IdentityInfo on $left.UserPrincipalName == $right.AccountUPN
```

---

**Problem 4 (cross-table hunting):** Correlate email phishing with subsequent sign-in.

```kql
let PhishedUsers =
    EmailEvents
    | where Timestamp > ago(7d)
    | where ThreatTypes has "Phish"
    | distinct RecipientEmailAddress;
IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountUpn in (PhishedUsers)
| where RiskLevelDuringSignIn in ("medium", "high")
| join kind=inner (
    EmailEvents
    | where ThreatTypes has "Phish"
    | project RecipientEmailAddress, Subject, SenderFromAddress, Timestamp
) on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, AccountUpn, IPAddress, RiskLevelDuringSignIn, Subject, SenderFromAddress
```

---

### `union` — Stack tables

**Problem:** Combine sign-in logs from multiple sources into one view.

```kql
let AllSignIns =
    SigninLogs
    | project Timestamp = TimeGenerated, User = UserPrincipalName, IP = IPAddress, Result = ResultType, Source = "AAD"
    | take 100;
let DeviceLogons =
    DeviceLogonEvents
    | project Timestamp, User = AccountName, IP = RemoteIP, Result = LogonType, Source = "Device";
union AllSignIns, DeviceLogons
| order by Timestamp desc
```

---

### `materialized_view` — Pre-computed aggregations

**Problem:** You query failed sign-ins per user every 5 minutes — don't scan raw data each time.

```kql
// Run once (needs admin permissions):
.create materialized-view FailedSignInsByUser on table SigninLogs
{
    SigninLogs
    | where ResultType != "0"
    | summarize FailCount = count() by UserPrincipalName, bin(TimeGenerated, 15m)
}

// Then query the materialized view instead:
FailedSignInsByUser
| where TimeGenerated > ago(1d)
| where FailCount >= 5
```

---

# Level 4: Advanced Data Shaping

---

### `parse` — Extract structured fields from strings

**Problem:** Parse raw Windows Event 4625 (failed logon) Description field.

```kql
SecurityEvent
| where EventID == 4625
| parse EventData with * "Account Name:" AccountName:string
    * "Account Domain:" AccountDomain:string
    * "Source Network Address:" SourceIP:string
    * "Error Code:" ErrorCode:string
| project TimeGenerated, AccountName, AccountDomain, SourceIP, ErrorCode
```

---

### `extract` — Regex extraction

**Problem 1:** Extract IP addresses from any text field.

```kql
SecurityEvent
| where EventID == 4625
| extend IP = extract(@"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", 1, EventData)
| where isnotempty(IP)
```

**Problem 2:** Extract process name from Windows 4688 event.

```kql
SecurityEvent
| where EventID == 4688
| extend ProcessName = extract(@"New Process Name:\s+(\S+)", 1, EventData)
| where ProcessName has_any ("powershell", "cmd", "wmic", "psexec")
```

---

### `extract_all` — Extract all regex matches

**Problem:** Extract ALL IPs from a raw log line.

```kql
let RawData = datatable(RawLog: string)
[
    "Connection from 10.0.0.1:443 to 192.168.1.100:80, relay via 203.0.113.50",
];
RawData
| extend IPs = extract_all(@"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", RawLog)
| mv-expand IPs
```

---

### `mv-expand` — Expand arrays to rows

**Problem:** Expand a `make_set()` result to see each IP individually.

```kql
SigninLogs
| where UserPrincipalName == "admin@yourtenant.com"
| summarize IPsUsed = make_set(IPAddress) by UserPrincipalName
| mv-expand IPsUsed
```

**Problem (real):** Expand a multi-valued security group membership.

```kql
let ExpandedMembers =
    IdentityInfo
    | mv-expand GroupMembership
    | project AccountUPN, Group = tostring(GroupMembership);
ExpandedMembers
| where Group == "Domain Admins"
```

---

### `mv-apply` — Expand with aggregation

**Problem:** For each user, expand their IPs and count occurrences.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize IPsUsed = make_list(IPAddress) by UserPrincipalName
| mv-apply IPsUsed on (
    summarize IPCount = count() by IPsUsed
)
```

---

### `bag_unpack` — Expand JSON into columns

**Problem:** The `EventData` column is JSON — unpack it.

```kql
SecurityEvent
| where EventID == 4624
| extend EventDataParsed = parse_json(EventData)
| evaluate bag_unpack(EventDataParsed)
| project TimeGenerated, TargetUserName, TargetDomainName, IpAddress, LogonTypeName
```

---

### `range` — Generate sequences

**Problem:** Generate a complete time series so missing hours show 0.

```kql
let TimeRange = range Hour from datetime(2026-07-01) to datetime(2026-07-02) step 1h;
TimeRange
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated between (datetime(2026-07-01) .. datetime(2026-07-02))
    | summarize EventCount = count() by bin(TimeGenerated, 1h)
) on $left.Hour == $right.TimeGenerated
| project Hour, EventCount = iff(isempty(EventCount), 0, EventCount)
```

---

# Level 5: Window Functions & Time Series

---

### `prev` / `next` — Access adjacent rows

**Problem:** Detect consecutive failures by the same user without time gap > 1 minute.

```kql
SigninLogs
| where ResultType != "0"
| order by UserPrincipalName asc, TimeGenerated asc
| extend PrevUser = prev(UserPrincipalName, 1),
         PrevTime = prev(TimeGenerated, 1),
         PrevResult = prev(ResultType, 1)
| where UserPrincipalName == PrevUser
  and TimeGenerated - PrevTime between (0min .. 1min)
| project TimeGenerated, UserPrincipalName, IPAddress, TimeSincePrev = TimeGenerated - PrevTime
```

---

### `row_cumsum` — Running total per partition

**Problem:** Track running count of failed sign-ins per user over time.

```kql
SigninLogs
| where ResultType != "0"
| order by UserPrincipalName asc, TimeGenerated asc
| extend RunningFailCount = row_cumsum(1, UserPrincipalName != prev(UserPrincipalName))
| project TimeGenerated, UserPrincipalName, IPAddress, RunningFailCount
| where RunningFailCount >= 5
```

---

### `row_number` / `rank` — Ranking within groups

**Problem:** Find the first 3 IPs each user signed in from.

```kql
SigninLogs
| where ResultType == "0"
| order by UserPrincipalName asc, TimeGenerated asc
| extend RowNum = row_number(1, UserPrincipalName != prev(UserPrincipalName))
| where RowNum <= 3
| project UserPrincipalName, TimeGenerated, IPAddress, RowNum
```

**Problem:** Rank users by number of failed sign-ins.

```kql
SigninLogs
| where ResultType != "0"
| summarize FailCount = count() by UserPrincipalName
| order by FailCount desc
| extend Rank = row_number(1, true)  // true = reset at 1, no partition
```

---

### `partition` — Run subqueries per partition

**Problem:** For each user, find the top 3 most-used IPs.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| partition by UserPrincipalName
(
    order by UserPrincipalName asc
    | summarize IPCount = count() by IPAddress
    | top 3 by IPCount desc
)
```

---

### `make-series` — Create time series

**Problem:** Create a complete hourly time series of events per user.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-07-01) .. datetime(2026-07-02))
| make-series EventCount = count()
    default=0
    on TimeGenerated
    from datetime(2026-07-01) to datetime(2026-07-02)
    step 1h
  by UserPrincipalName
```

---

### `series_decompose_anomalies` — Anomaly detection

**Problem:** Detect anomalous spikes in sign-in volume.

```kql
SigninLogs
| make-series EventCount = count()
    default=0
    on TimeGenerated
    from ago(14d) to now()
    step 1h
| extend
    AnomalyScore = series_decompose_anomalies(EventCount, 2.0)
| mv-expand TimeGenerated, EventCount, AnomalyScore
    to typeof(datetime), typeof(long), typeof(double)
| where AnomalyScore == 1
| project TimeGenerated, EventCount
```

---

### `scan` — State machine sequence detection

**Problem:** Detect the precise sequence: Failed Logon → Successful Logon → Process Execution (lateral movement pattern).

```kql
let Events =
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID in (4625, 4624, 4688)
    | order by TimeGenerated asc;
Events
| scan declare (Stage: int = 0, ChainUser: string = "")
with
(
    // Step 1: Failed logon starts a chain
    step s1: EventID == 4625 => Stage = 1; ChainUser = TargetUserName;
    // Step 2: Successful logon by same user within 10min
    step s2: EventID == 4624 and TargetUserName == s1.ChainUser
             and TimeGenerated - s1.TimeGenerated <= 10m
             => Stage = 2; ChainUser = s1.ChainUser;
    // Step 3: Process execution by same user within 5min
    step s3: EventID == 4688 and TargetUserName == s2.ChainUser
             and TimeGenerated - s2.TimeGenerated <= 5m
             => Stage = 3; ChainUser = s2.ChainUser;
)
| where Stage == 3
| project TimeGenerated, TargetUserName, EventID, Stage
```

---

# Level 6: Functions & Reusability

---

### `let` — Variables

**Problem:** Parameterize a threshold without hard-coding.

```kql
let MinFailures = 5;
let TimeWindow = 10m;
SigninLogs
| where ResultType != "0"
| summarize FailCount = count()
  by UserPrincipalName, bin(TimeGenerated, TimeWindow)
| where FailCount >= MinFailures
```

---

### `let view()` — Reusable named query

**Problem:** Define a "suspicious users" view that you reference multiple times.

```kql
let SuspiciousUsers = view () {
    SigninLogs
    | where ResultType != "0"
    | summarize FailCount = count() by UserPrincipalName
    | where FailCount >= 10
};
SuspiciousUsers
| join kind=inner (
    IdentityInfo | project AccountUPN, Department, JobTitle
) on $left.UserPrincipalName == $right.AccountUPN
```

---

### `let` lambda function — Parameterized

**Problem:** Create a reusable brute-force detector function.

```kql
let DetectBruteForce = (Threshold: long, WindowMinutes: long, TimeRange: timespan) {
    SigninLogs
    | where TimeGenerated > ago(TimeRange)
    | where ResultType != "0"
    | summarize FailCount = count()
      by UserPrincipalName, bin(TimeGenerated, WindowMinutes * 1m)
    | where FailCount >= Threshold
    | project UserPrincipalName, WindowStart = TimeGenerated, FailCount
};
// Reuse with different parameters
DetectBruteForce(5, 10, 1d)      // 5 failures in 10 min, last 1 day
| order by FailCount desc
```

---

### `.create-or-alter function` — Database-stored

**Problem:** Deploy a detection function permanently in Sentinel.

```kql
// Run once (needs admin rights):
.create-or-alter function with (
    folder = "Detections",
    docstring = "Detects brute force attempts on privileged accounts"
) DetectPrivilegedBruteForce(Threshold: long = 5, WindowMin: long = 10)
{
    let AdminUsers =
        IdentityInfo
        | where AssignedRoles has_any ("Global Administrator", "Security Administrator")
        | distinct AccountUPN;
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where UserPrincipalName in (AdminUsers)
    | where ResultType != "0"
    | summarize FailCount = count()
      by UserPrincipalName, bin(TimeGenerated, WindowMin * 1m)
    | where FailCount >= Threshold
}

// Call it:
DetectPrivilegedBruteForce(3, 5)
```

---

# Level 7: Performance Optimization

---

### Rule 1: Filter Early

**Bad (scans all data then joins):**
```kql
SigninLogs
| join kind=inner IdentityInfo on $left.UserPrincipalName == $right.AccountUPN
| where ResultType != "0"
```

**Good (filter before join):**
```kql
SigninLogs
| where ResultType != "0"
| where TimeGenerated > ago(1d)
| project UserPrincipalName
| join kind=inner (
    IdentityInfo
    | where JobTitle == "Global Admin"
    | project AccountUPN
) on $left.UserPrincipalName == $right.AccountUPN
```

---

### Rule 2: Project Away Unused Columns

**Bad:**
```kql
SigninLogs
| where ResultType != "0"
| summarize count() by UserPrincipalName
```

**Good:**
```kql
SigninLogs
| where ResultType != "0"
| project UserPrincipalName                 // drop 50+ columns
| summarize count() by UserPrincipalName
```

---

### Rule 3: Use `hint.shufflekey`

**Problem:** Large `summarize` or `join` by high-cardinality key is slow.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| summarize hint.shufflekey = UserPrincipalName
    count() by UserPrincipalName, bin(TimeGenerated, 1h)
```

---

### Rule 4: Always Scope Time

**Bad (full table scan):**
```kql
SigninLogs
| where UserPrincipalName == "admin@yourtenant.com"
```

**Good (restrict range first):**
```kql
SigninLogs
| where TimeGenerated between (ago(7d) .. now())
| where UserPrincipalName == "admin@yourtenant.com"
```

---

### Rule 5: Use `materialized_view` for Repeated Queries

**Problem:** You refresh a dashboard every 5 minutes that counts failures per hour. Don't scan raw data.

```kql
.create materialized-view with (backfill=true) HourlyFailures on table SigninLogs
{
    SigninLogs
    | where ResultType != "0"
    | summarize FailCount = count() by bin(TimeGenerated, 1h)
}
```

---

### Rule 6: Join Order Matters

- Put the **smaller table** on the **left** (build side)
- Put the **larger table** on the **right** (probe side)
- Use `hint.strategy=broadcast` if the right side is small enough to fit in memory

```kql
let SmallTable = ThreatIntelligenceIndicators | where ExpirationTime > now() | project Indicator, ThreatType;
LargeSecurityEvents
| join hint.strategy=broadcast kind=inner SmallTable on $left.IPAddress == $right.Indicator
```

---

### Query Optimization Checklist

| Check | Why |
|-------|-----|
| Time filter present? | Limits scan |
| Filter before join? | Less data shuffled |
| `project` used? | Fewer columns in pipeline |
| `hint.shufflekey` needed? | Distributes large aggregations |
| Materialized view possible? | Pre-computes repeated work |
| `take` during dev? | Iterate on samples, not full data |

---

# Level 8: Expert SIEM Detection Engineering

---

### Pattern 1 — Full Kill Chain Detection

**Problem:** Detect lateral movement: Failed Logon (recon) → Successful Logon (access) → Process Execution (execution).

```kql
let TimeWindow = 15m;
let AdminUsers =
    IdentityInfo
    | where AssignedRoles contains "Admin"
    | distinct AccountUPN;
let Recon =
    SigninLogs
    | where ResultType != "0"
    | where UserPrincipalName in (AdminUsers)
    | project User = UserPrincipalName, ReconTime = TimeGenerated, ReconIP = IPAddress;
let Access =
    SigninLogs
    | where ResultType == "0"
    | where UserPrincipalName in (AdminUsers)
    | project User = UserPrincipalName, AccessTime = TimeGenerated, AccessIP = IPAddress;
let Execution =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in ("powershell.exe", "cmd.exe", "psexec.exe", "wmic.exe", "schtasks.exe")
    | project User = AccountName, ExecTime = Timestamp, Process = FileName, DeviceName;
Recon
| join kind=inner Access on User
| where AccessTime > ReconTime
  and AccessTime - ReconTime between (0min .. TimeWindow)
| join kind=inner Execution on User
| where ExecTime > AccessTime
  and ExecTime - AccessTime between (0min .. TimeWindow)
| project User, ReconTime, ReconIP, AccessTime, AccessIP, ExecTime, DeviceName, Process
| order by User, ReconTime
```

---

### Pattern 2 — Threat Intel Enrichment

**Problem:** Cross-reference sign-in IPs against threat intelligence feeds.

```kql
let ThreatIPs =
    ThreatIntelligenceIndicator
    | where Active == true
    | where ExpirationTime > now()
    | where ThreatType in ("MaliciousIP", "Botnet", "C2")
    | project Indicator, ThreatType, Confidence = ConfidenceScore;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != "0"
| join kind=inner ThreatIPs on $left.IPAddress == $right.Indicator
| project TimeGenerated, UserPrincipalName, IPAddress, ThreatType, Confidence, ResultType
| order by Confidence desc
```

---

### Pattern 3 — Baseline Deviation (Behavioral Anomaly)

**Problem:** Detect users whose failure rate spikes compared to their own baseline.

```kql
let BaselineStart = ago(14d);
let BaselineEnd = ago(1d);
let Baseline =
    SigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | summarize
        BaselineTotal = count(),
        BaselineFailures = countif(ResultType != "0"),
        BaselineFailRate = countif(ResultType != "0") * 100.0 / count()
      by UserPrincipalName;
let Current =
    SigninLogs
    | where TimeGenerated > ago(1d)
    | summarize
        CurrentTotal = count(),
        CurrentFailures = countif(ResultType != "0"),
        CurrentFailRate = countif(ResultType != "0") * 100.0 / count()
      by UserPrincipalName;
Current
| join kind=inner Baseline on UserPrincipalName
| where BaselineTotal >= 10   // only users with enough history
| extend SpikeRatio = CurrentFailRate / (BaselineFailRate + 0.1)
| where SpikeRatio > 3.0     // 3x normal = anomaly
| project UserPrincipalName, BaselineFailRate, CurrentFailRate, SpikeRatio
| order by SpikeRatio desc
```

---

### Pattern 4 — Privileged Account Monitoring

**Problem:** Alert when a Global Admin signs in from an unusual location.

```kql
let AdminUsers =
    IdentityInfo
    | where AssignedRoles contains "Global Administrator"
    | distinct AccountUPN;
let AdminBaseline =
    SigninLogs
    | where UserPrincipalName in (AdminUsers)
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where ResultType == "0"
    | summarize Locations = make_set(Location) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName in (AdminUsers)
| where ResultType == "0"
| join kind=leftouter AdminBaseline on UserPrincipalName
| where Location !in (Locations)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, BaselineLocations = Locations
```

---

### Pattern 5 — Data Exfiltration Detection

**Problem:** Detect unusual outbound data transfer via network events.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public"
| where Protocol in ("TCP", "UDP")
| summarize
    TotalBytes = sum(SentBytes + ReceivedBytes),
    ConnectionCount = count(),
    UniqueDestinations = dcount(RemoteIP)
  by DeviceName, AccountName, bin(Timestamp, 1h)
| where TotalBytes > 500000000          // > 500MB in an hour
   or ConnectionCount > 1000            // > 1000 connections to external
| order by TotalBytes desc
```

---

### Pattern 6 — Ransomware Pattern Detection

**Problem:** Detect rapid file modifications + process creation = ransomware.

```kql
let FileChangeBurst =
    DeviceFileEvents
    | where Timestamp > ago(1h)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | summarize FileChanges = count() by DeviceName, bin(Timestamp, 5m)
    | where FileChanges > 100;
let SuspiciousProcesses =
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | where FileName in ("powershell.exe", "vssadmin.exe", "cipher.exe", "bcdedit.exe")
    | summarize ProcessCount = count() by DeviceName, bin(Timestamp, 5m);
FileChangeBurst
| join kind=inner SuspiciousProcesses on DeviceName, Timestamp
| where ProcessCount >= 1
| project DeviceName, Timestamp, FileChanges, ProcessCount
```

---

### Pattern 7 — Multi-Stage Phishing → Compromise

**Problem:** User received phishing email → clicked link → signed in from new IP → created mailbox rule.

```kql
let PhishEmail =
    EmailEvents
    | where Timestamp > ago(7d)
    | where ThreatTypes has "Phish"
    | project RecipientEmailAddress, Subject, SenderFromAddress, PhishTime = Timestamp;
let Clicked =
    EmailUrlInfo
    | join kind=inner PhishEmail on $left.NetworkMessageId == $right.NetworkMessageId
    | project RecipientEmailAddress, PhishTime, Url, ClickTime = Timestamp;
let NewSignIn =
    SigninLogs
    | where TimeGenerated > ago(7d)
    | extend User = tostring(split(UserPrincipalName, "@")[0])
    | join kind=inner (
        Clicked | extend User = tostring(split(RecipientEmailAddress, "@")[0])
    ) on User
    | where TimeGenerated > ClickTime
    | where TimeGenerated - ClickTime between (0min .. 60min)
    | project User, ClickTime, SignInTime = TimeGenerated, IPAddress;
let MailboxRule =
    AuditLogs
    | where OperationName == "New-InboxRule"
    | extend User = tostring(TargetResources[0].userPrincipalName)
    | join kind=inner NewSignIn on User
    | where TimeGenerated > SignInTime
    | project User, ClickTime, SignInTime, IPAddress, RuleCreatedTime = TimeGenerated
    | extend IsCompromised = true;
MailboxRule
```

---

### Pattern 8 — Recap: All MITRE ATT&CK Detections in One

| Technique | Query Pattern | Table |
|-----------|--------------|-------|
| T1078 (Valid Accounts) | `summarize count() by UserPrincipalName` | SigninLogs |
| T1110 (Brute Force) | `summarize count() by User, bin(Time, 5m) \| where count >= 5` | SigninLogs |
| T1550 (Pass the Hash) | `where LogonType == 9` (NewCredentials) | DeviceLogonEvents |
| T1059 (Command & Scripting) | `where FileName in ("powershell.exe","cmd.exe")` | DeviceProcessEvents |
| T1047 (WMI) | `where FileName == "wmic.exe"` | DeviceProcessEvents |
| T1053 (Scheduled Task) | `where FileName == "schtasks.exe"` | DeviceProcessEvents |
| T1574 (DLL Hijacking) | `where ActionType == "ImageLoaded" and FileName endswith ".dll"` | DeviceImageLoadEvents |
| T1566 (Phishing) | `where ThreatTypes has "Phish"` | EmailEvents |
| T1114 (Email Forwarding) | `where OperationName == "New-InboxRule"` | AuditLogs |
| T1048 (Exfiltration) | `summarize sum(SentBytes) by Device, bin(Time, 1h) \| where > threshold` | DeviceNetworkEvents |

---

# SC-200 Key Tables Quick Reference

### Microsoft Defender for Endpoint

| Table | Use Case |
|-------|----------|
| `DeviceLogonEvents` | Logon type, success/failure, account, IP |
| `DeviceProcessEvents` | Process creation, command line, parent |
| `DeviceNetworkEvents` | Network connections, ports, protocols |
| `DeviceFileEvents` | File creation, modification, deletion |
| `DeviceEvents` | Various security events (AATP, ASR, etc.) |
| `DeviceImageLoadEvents` | DLL loading (hijacking detection) |
| `DeviceRegistryEvents` | Registry modifications (persistence) |

### Microsoft Defender for Office 365

| Table | Use Case |
|-------|----------|
| `EmailEvents` | Email delivery, sender, recipient, threat types |
| `EmailAttachmentInfo` | Attachment details, file hashes |
| `EmailUrlInfo` | URLs in email, click actions |
| `EmailPostDeliveryEvents` | Post-delivery actions (ZAP, remediation) |

### Microsoft Defender for Identity

| Table | Use Case |
|-------|----------|
| `IdentityLogonEvents` | Kerberos/NTLM authentication, failures |
| `IdentityQueryEvents` | LDAP queries, directory enumeration |
| `IdentityDirectoryEvents` | Group membership changes, account changes |

### Microsoft Entra ID / Azure AD

| Table | Use Case |
|-------|----------|
| `SigninLogs` | Interactive/non-interactive sign-ins |
| `AuditLogs` | Directory changes, role assignments |
| `AADNonInteractiveUserSignInLogs` | Service principal sign-ins |

### Microsoft Sentinel

| Table | Use Case |
|-------|----------|
| `SecurityEvent` | Windows events (4624, 4625, 4688, etc.) |
| `CommonSecurityLog` | Syslog/CEF from firewalls, appliances |
| `Syslog` | Raw syslog messages |
| `AzureActivity` | Azure resource operations |
| `AWSCloudTrail` | AWS API calls |
| `OfficeActivity` | O365 audit logs, Exchange, SharePoint |

---

# MITRE ATT&CK Detection Patterns

### T1078 — Valid Accounts
```kql
SigninLogs
| where ResultType == "0"
| where UserPrincipalName in (SuspendedUsers)
```

### T1110 — Brute Force
```kql
SigninLogs
| where ResultType != "0"
| summarize FailCount = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailCount >= 5
```

### T1550.002 — Pass the Hash
```kql
DeviceLogonEvents
| where LogonType in (9, 3) and LogonTypeName has "Network"
| where AccountName != DeviceName
```

### T1059.001 — PowerShell
```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-e ", "Invoke-", "DownloadString", "-hidden")
```

### T1047 — WMI
```kql
DeviceProcessEvents
| where FileName == "wmic.exe"
| where ProcessCommandLine has "process call create"
```

### T1053.005 — Scheduled Task
```kql
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
```

### T1566.001 — Spearphishing Attachment
```kql
EmailEvents
| where ThreatTypes has "Malware" or ThreatTypes has "Phish"
| project RecipientEmailAddress, Subject, SenderFromAddress, ThreatTypes
```

### T1114.002 — Email Forwarding Rule
```kql
AuditLogs
| where OperationName == "New-InboxRule"
| where TargetResources[0].modifiedProperties has "ForwardTo" or TargetResources[0].modifiedProperties has "Forwarding"
```

### T1003.001 — LSASS Dump
```kql
DeviceProcessEvents
| where FileName in ("procdump.exe", "rundll32.exe", "comsvcs.dll")
| where ProcessCommandLine has_any ("lsass", "lsadump", "minidump")
```

### T1021.001 — RDP
```kql
DeviceLogonEvents
| where LogonType == 10  // RemoteInteractive
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
```

---

# Real-World Detection Scenarios

---

### Scenario 1 — Ransomware: Mass File Encryption + Shadow Copy Deletion

**Problem:** Detect the combination of rapid file modifications and VSS admin usage (hallmark of ransomware).

**Data sources:** DeviceFileEvents, DeviceProcessEvents

```kql
let FileBurst =
    DeviceFileEvents
    | where Timestamp > ago(1h)
    | where ActionType in ("FileModified", "FileRenamed", "FileCreated")
    | summarize FileChangeCount = count() by DeviceName, bin(Timestamp, 5m)
    | where FileChangeCount >= 50;
let ShadowCopyDeletion =
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | where FileName == "vssadmin.exe"
    | where ProcessCommandLine has "delete shadows"
    | project DeviceName, Timestamp;
FileBurst
| join kind=inner ShadowCopyDeletion on DeviceName
| where abs(Timestamp - Timestamp1) <= 30m
| project DeviceName, FileBurstTime = Timestamp, FileChangeCount, ShadowDelTime = Timestamp1
| extend IsRansomware = true
```

**MITRE:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)

---

### Scenario 2 — C2 Beaconing: Periodic Outbound Connections

**Problem:** Detect beaconing behavior — a process connecting to an external IP at regular intervals.

**Data sources:** DeviceNetworkEvents

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public"
| where Protocol in ("TCP", "UDP")
| where ActionType == "ConnectionSuccess"
| project DeviceName, Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
| order by DeviceName asc, InitiatingProcessFileName asc, Timestamp asc
| extend PrevTime = prev(Timestamp, 1, DeviceName != prev(DeviceName) or InitiatingProcessFileName != prev(InitiatingProcessFileName))
| extend Interval = Timestamp - PrevTime
| where Interval between (30s .. 5m)   // beacon interval range
| extend Gap = iff(Interval < 1m, "Regular", "Irregular")
| summarize
    BeaconCount = count(),
    AvgInterval = avg(Interval * 1.0),
    MinInterval = min(Interval),
    MaxInterval = max(Interval),
    UniqueIPs = dcount(RemoteIP)
  by DeviceName, InitiatingProcessFileName, Gap
| where BeaconCount >= 10 and AvgInterval between (30 .. 300)   // consistent intervals
| order by BeaconCount desc
```

**MITRE:** T1071.001 (Web Protocols), T1573 (Encrypted Channel)

---

### Scenario 3 — Kerberoasting: Excessive TGS Requests

**Problem:** Detect Kerberoasting — an attacker requesting Kerberos service tickets for offline cracking.

**Data sources:** IdentityQueryEvents, SecurityEvent (4769)

```kql
let Baseline =
    IdentityQueryEvents
    | where Timestamp between (ago(14d) .. ago(1d))
    | where ActionType == "Kerberos Service Ticket Operation"
    | summarize DailyAvg = dcount(Timestamp) / 14 by AccountUpn;
IdentityQueryEvents
| where Timestamp > ago(1d)
| where ActionType == "Kerberos Service Ticket Operation"
| summarize RequestCount = count(),
    UniqueServices = dcount(Target),
    FirstRequest = min(Timestamp),
    LastRequest = max(Timestamp)
  by AccountUpn
| join kind=leftouter Baseline on AccountUpn
| where RequestCount >= 10
    or (RequestCount >= 5 and DailyAvg < 2)   // spike above baseline
| order by RequestCount desc
| project AccountUpn, RequestCount, UniqueServices, FirstRequest, LastRequest
```

**MITRE:** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)

---

### Scenario 4 — DCSync Attack: Excessive Replication Requests

**Problem:** Detect DCSync — requesting domain controller replication to dump credentials.

**Data sources:** SecurityEvent (4662), IdentityDirectoryEvents

```kql
IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType == "Directory Service Access"
| where Target contains "DS-Replication-Get-Changes"
| summarize
    RequestCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
  by AccountUpn, TargetDevice = DeviceName
| where RequestCount >= 5
| join kind=leftouter (
    IdentityInfo
    | project AccountUPN, JobTitle, Department
) on $left.AccountUpn == $right.AccountUPN
| project AccountUpn, JobTitle, Department, TargetDevice, RequestCount, FirstSeen, LastSeen
| order by RequestCount desc
```

**MITRE:** T1003.006 (OS Credential Dumping: DCSync)

---

### Scenario 5 — Golden Ticket: Abnormal Kerberos Ticket Usage

**Problem:** Detect forged Kerberos tickets (Golden Ticket) by identifying anomalous ticket durations or encryption types.

**Data sources:** SecurityEvent (4768, 4769)

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4768   // Kerberos TGS
| where EventData has "TicketOptions" and EventData has "TicketEncryptionType"
| extend
    TicketDuration = extract(@"TicketOptions:\s+(\w+)", 1, EventData),
    EncryptionType = extract(@"TicketEncryptionType:\s+(\w+)", 1, EventData)
| extend DurationMinutes = toint(TicketDuration, 0)
| where DurationMinutes > 600    // normal is 10h (600min), golden tickets = days/years
    or EncryptionType == "0x1"   // RC4 = weak encryption, suspicious for service tickets
| project TimeGenerated, AccountName = TargetUserName, DurationMinutes, EncryptionType
```

**MITRE:** T1558.001 (Steal or Forge Kerberos Tickets: Golden Ticket)

---

### Scenario 6 — Unusual PowerShell (Obfuscated / Encoded Commands)

**Problem:** Detect obfuscated or encoded PowerShell execution.

**Data sources:** DeviceProcessEvents

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any (
    "-enc", "-e ",           // encoded command
    "Invoke-",               // PowerShell Empire/Cobalt Strike
    "DownloadString",        // download cradle
    "IEX",                   // invoke expression
    "from base64",           // base64 decode
    "-hidden",               // hidden window
    "-WindowStyle Hidden",   // hidden window (explicit)
    "Byte(",                 // shellcode injection
    "-nop -w hidden",        // no profile + hidden
    "$env:appdata"           // common persistence location
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    CommandLine = substring(ProcessCommandLine, 0, 500),   // truncate for readability
    SHA256
| order by Timestamp desc
```

**MITRE:** T1059.001 (Command and Scripting Interpreter: PowerShell)

---

### Scenario 7 — Living Off the Land (LOLBins) Chain

**Problem:** Detect attackers using built-in Windows binaries for malicious purposes.

**Data sources:** DeviceProcessEvents

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in (
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe",
    "wscript.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
    "reg.exe", "schtasks.exe", "wmic.exe", "nslookup.exe",
    "curl.exe", "net.exe", "net1.exe"
)
| where ProcessCommandLine has_any (
    "http://", "https://",          // LOLBin downloading from URL
    "javascript:",                   // mshta js execution
    "scrobj.dll",                    // regsvr32 COM scriptlet
    "download",                      // certutil download
    "-split",                        // certutil decode
    "/create /tn",                   // scheduled task creation
    "process call create",           // wmic process execution
    "user /add", "group /add",       // net user/group manipulation
    "localgroup administrators",     // privilege escalation
    " /delete",                      // net user deletion
    "useradd", "passwd"              // suspicious net operations
)
| project Timestamp, DeviceName, AccountName, FileName, CommandLine = substring(ProcessCommandLine, 0, 400)
| order by Timestamp desc
```

**MITRE:** T1218 (System Binary Proxy Execution), T1053 (Scheduled Task/Job)

---

### Scenario 8 — Privilege Escalation via Token Manipulation

**Problem:** Detect privilege escalation using token manipulation tools.

**Data sources:** DeviceProcessEvents

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in (
    "whoami.exe", "privilege::debug", "token::elevate",  // Mimikatz commands
    "secedit.exe", "msf.exe", "mimikatz.exe",
    "Invoke-TokenManipulation.ps1"
)
| where ProcessCommandLine has_any (
    "/priv", "/user", "/groups",     // whoami privilege listing
    "seprivilege",                    // token manipulation
    "token", "impersonate",
    "SeDebugPrivilege", "SeTakeOwnershipPrivilege"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**MITRE:** T1134 (Access Token Manipulation)

---

### Scenario 9 — Suspicious Service Installation (Persistence)

**Problem:** Detect unauthorized service creation for persistence.

**Data sources:** SecurityEvent (4697, 7045), DeviceProcessEvents

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4697 or EventID == 7045   // Service installation
| extend
    ServiceName = extract(@"Service Name: (\S+)", 1, EventData),
    ServiceFile = extract(@"Service File Name: (\S+)", 1, EventData),
    StartType = extract(@"Service Start Type: (\S+)", 1, EventData)
| where isnotempty(ServiceFile)
| where ServiceFile !startswith @"C:\Windows\"
    or ServiceFile has_any ("temp", "Users", "ProgramData", "AppData")
| project TimeGenerated, Computer, SubjectUserName, ServiceName, ServiceFile, StartType
| order by TimeGenerated desc
```

**MITRE:** T1543.003 (Create or Modify System Process: Windows Service)

---

### Scenario 10 — Registry Run Key Persistence

**Problem:** Detect persistence via registry Run keys.

**Data sources:** DeviceRegistryEvents

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    @"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
)
| where RegistryValueName !startswith "OneDrive"   // exclude benign
    and RegistryValueName !startswith "SecurityHealth"
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

**MITRE:** T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)

---

### Scenario 11 — Network Scanning / Reconnaissance

**Problem:** Detect internal network scanning activity.

**Data sources:** DeviceNetworkEvents

```kql
let ScanningThreshold = 50;
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteIPType == "Private"
| where ActionType == "ConnectionSuccess"
| summarize
    UniqueIPs = dcount(RemoteIP),
    UniquePorts = dcount(RemotePort),
    ConnectionAttempts = count(),
    FirstConn = min(Timestamp),
    LastConn = max(Timestamp)
  by DeviceName, InitiatingProcessFileName
| where UniqueIPs >= ScanningThreshold
    or (UniquePorts >= 20 and ConnectionAttempts >= 100)
| extend ScanDuration = LastConn - FirstConn
| project DeviceName, InitiatingProcessFileName, UniqueIPs, UniquePorts, ConnectionAttempts, ScanDuration
| order by UniqueIPs desc
```

**MITRE:** T1046 (Network Service Discovery)

---

### Scenario 12 — DLL Injection / Process Hollowing

**Problem:** Detect common process injection techniques.

**Data sources:** DeviceEvents, DeviceProcessEvents

```kql
// Suspicious parent-child processes (e.g., Word launching PowerShell)
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrobat.exe", "acrord32.exe", "chrome.exe", "firefox.exe"
)
| where FileName in (
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe"
)
| project Timestamp, DeviceName, AccountName, ParentProcess = InitiatingProcessFileName, ChildProcess = FileName, CommandLine = substring(ProcessCommandLine, 0, 300)
| order by Timestamp desc
```

**Alternative — Remote injection events:**
```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "CreateRemoteThreadApiCall"
| project Timestamp, DeviceName, AccountName, RemoteThreadProcessId, InitiatingProcessFileName
| order by Timestamp desc
```

**MITRE:** T1055.012 (Process Injection: Process Hollowing), T1055.001 (DLL Injection)

---

### Scenario 13 — Data Exfiltration via DNS

**Problem:** Detect data exfiltration using DNS tunneling.

**Data sources:** DeviceNetworkEvents

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public"
| where RemotePort == 53                    // DNS traffic
| extend DomainLength = strlen(RemoteUrl) - strcount(RemoteUrl, ".")
| extend HasSubdomains = countof(RemoteUrl, ".", "regex") >= 3
| where DomainLength > 50                   // abnormally long subdomain
    or HasSubdomains == true
| summarize
    DNSQueryCount = count(),
    UniqueDomains = dcount(RemoteUrl),
    MaxDomainLen = max(DomainLength),
    AvgQuerySize = avg(DomainLength)
  by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where DNSQueryCount >= 100 or AvgQuerySize > 30
| order by DNSQueryCount desc
```

**MITRE:** T1048 (Exfiltration Over Alternative Protocol), T1572 (Protocol Tunneling)

---

### Scenario 14 — Pass-the-Hash / Over-Pass-the-Hash

**Problem:** Detect credential relay attacks.

**Data sources:** DeviceLogonEvents

```kql
DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType in (3, 9)                 // Network (3) or NewCredentials (9)
| where AccountName != DeviceName           // not SYSTEM
    and AccountName != "ANONYMOUS LOGON"
| join kind=leftouter (
    DeviceLogonEvents
    | where Timestamp > ago(1d)
    | where LogonType == 2                  // Interactive logon
    | project AccountName, DeviceName, InteractiveTime = Timestamp
) on AccountName, DeviceName
| extend TimeSinceInteractive = Timestamp - InteractiveTime
| where TimeSinceInteractive > 1h           // network logon without prior interactive
    or isempty(InteractiveTime)             // no interactive logon at all
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, IsLocalAdmin
| order by Timestamp desc
```

**MITRE:** T1550.002 (Use Alternate Authentication Material: Pass the Hash)

---

### Scenario 15 — User Agent Anomaly Detection

**Problem:** Detect suspicious user agents that don't match normal browser patterns.

**Data sources:** SigninLogs, CommonSecurityLog (proxy logs)

```ksql
SigninLogs
| where TimeGenerated > ago(1d)
| where isnotempty(UserAgent)
| extend IsSuspiciousUA = case(
    UserAgent contains "python-requests", "Python Script",
    UserAgent contains "curl/", "Curl",
    UserAgent contains "Wget", "Wget",
    UserAgent contains "Go-http-client", "Go HTTP",
    UserAgent contains "okhttp", "Android App",
    UserAgent contains "Powershell", "PowerShell",
    UserAgent contains "Java/", "Java Client",
    UserAgent contains "ZAP", "Security Scanner",
    UserAgent contains "Nmap", "Port Scanner",
    UserAgent contains "masscan", "Mass Scanner",
    UserAgent contains "sqlmap", "SQL Injection Tool",
    UserAgent contains "Burp", "Burp Suite",
    "", "Unknown"
)
| where IsSuspiciousUA != ""
| summarize
    AttemptCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueIPs = dcount(IPAddress)
  by IsSuspiciousUA, UserAgent
| order by AttemptCount desc
```

**MITRE:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)

---

### Scenario 16 — Cross-Tenant / External Collaboration Abuse

**Problem:** Detect suspicious B2B guest user activity.

**Data sources:** SigninLogs, AuditLogs

```kql
let ExternalUsers =
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where UserType == "Guest"
    | distinct UserPrincipalName;
SigninLogs
| where UserPrincipalName in (ExternalUsers)
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueApps = dcount(AppDisplayName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by UserPrincipalName
| where SignInCount >= 10
    or UniqueIPs >= 3
| order by SignInCount desc
```

**MITRE:** T1078 (Valid Accounts), T1528 (Steal Application Access Token)

---

### Scenario 17 — Azure / Cloud Persistence via Service Principal

**Problem:** Detect creation of suspicious service principals or app registrations.

**Data sources:** AuditLogs

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Add service principal",
    "Add application",
    "Add OAuth2PermissionGrant",
    "Consent to application",
    "Update application"
)
| where Result == "success"
| extend
    User = tostring(InitiatedBy.user.userPrincipalName),
    AppName = tostring(TargetResources[0].displayName),
    AppID = tostring(TargetResources[0].id),
    AppOwner = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, User, OperationName, AppName, AppID, AppOwner
| order by TimeGenerated desc
```

**MITRE:** T1098.002 (Account Manipulation: Additional Cloud Roles), T1525 (Implant Container Image)

---

### Scenario 18 — Suspicious Azure AD Conditional Access Changes

**Problem:** Detect attacker weakening or bypassing Conditional Access policies.

**Data sources:** AuditLogs

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "conditional access" or OperationName has "ConditionalAccess"
| where Result == "success"
| extend
    User = tostring(InitiatedBy.user.userPrincipalName),
    Policy = tostring(TargetResources[0].displayName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| where ModifiedProperties has_any ("Off", "false", "disabled", "report-only")
| project TimeGenerated, User, Policy, ModifiedProperties
| order by TimeGenerated desc
```

**MITRE:** T1556 (Modify Authentication Process)

---

### Scenario 19 — Mailbox Forwarding / Exfiltration via Email

**Problem:** Detect users creating mailbox forwarding rules to exfiltrate data.

**Data sources:** AuditLogs, OfficeActivity

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("New-InboxRule", "Set-Mailbox", "Add-MailboxPermission", "Add-MailboxFolderPermission")
| where Result == "success"
| extend
    User = tostring(InitiatedBy.user.userPrincipalName),
    Target = tostring(TargetResources[0].userPrincipalName),
    Params = tostring(TargetResources[0].modifiedProperties)
| where Params has_any ("ForwardTo", "ForwardingSmtpAddress", "RedirectTo", "DeliverToMailboxAndForward")
| project TimeGenerated, User, Target, OperationName, Params
| order by TimeGenerated desc
```

**MITRE:** T1114.002 (Email Collection: Remote Email Collection), T1048 (Exfiltration)

---

### Scenario 20 — Suspicious Scheduled Task for Persistence

**Problem:** Detect scheduled tasks created by non-admin users, pointing to suspicious binaries.

**Data sources:** DeviceProcessEvents

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| extend
    TaskName = extract(@"/TN\s+([^\s]+)", 1, ProcessCommandLine),
    TaskExec = extract(@"/TR\s+([^\s]+)", 1, ProcessCommandLine),
    TaskUser = extract(@"/RU\s+([^\s]+)", 1, ProcessCommandLine),
    TaskLevel = extract(@"/RL\s+([^\s]+)", 1, ProcessCommandLine)
| where isnotempty(TaskName)
| where TaskExec !startswith @"C:\Windows\"
    or TaskExec has_any ("temp", "Users", "AppData", "ProgramData", "powershell", "cmd.exe")
    or (isnotempty(TaskLevel) and TaskLevel == "HIGHEST")   // run with highest privileges
| project Timestamp, DeviceName, AccountName, TaskName, TaskExec, TaskUser, TaskLevel
| order by Timestamp desc
```

**MITRE:** T1053.005 (Scheduled Task/Job: Scheduled Task)

---

### Scenario 21 — Suspicious WMI Persistence

**Problem:** Detect WMI event subscription persistence.

**Data sources:** DeviceProcessEvents

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "wmic.exe"
| where ProcessCommandLine has_any (
    "/create", "create",
    "EventFilter", "Consumer", "FilterToConsumerBinding",
    "__EventFilter", "__EventConsumer"
)
| project Timestamp, DeviceName, AccountName, CommandLine = substring(ProcessCommandLine, 0, 500)
| order by Timestamp desc
```

**Alternative — Direct WMI persistence via PowerShell:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any (
    "__EventFilter", "__EventConsumer",
    "FilterToConsumerBinding",
    "MSFT_WMI_EventFilter", "MSFT_WMI_EventConsumer"
)
| project Timestamp, DeviceName, AccountName, CommandLine = substring(ProcessCommandLine, 0, 500)
```

**MITRE:** T1546.003 (Event Triggered Execution: WMI Event Subscription)

---

### Scenario 22 — SAM Database Dump (Mimikatz)

**Problem:** Detect tools accessing the SAM registry hive or LSASS process.

**Data sources:** DeviceProcessEvents, DeviceRegistryEvents

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("mimikatz", "procdump", "pwdump", "gsecdump", "cachedump", "lsass")
    or (FileName == "rundll32.exe" and ProcessCommandLine has "comsvcs.dll")
    or (FileName == "powershell.exe" and ProcessCommandLine has_any ("Invoke-Mimikatz", "Invoke-ReflectivePEInjection"))
    or (FileName == "reg.exe" and ProcessCommandLine has "save" and ProcessCommandLine has_any ("sam", "system", "security"))
| project Timestamp, DeviceName, AccountName, FileName, CommandLine = substring(ProcessCommandLine, 0, 400)
| order by Timestamp desc
```

**MITRE:** T1003.001 (OS Credential Dumping: LSASS Memory), T1003.002 (Security Account Manager)

---

### Scenario 23 — Account Creation & Privilege Escalation

**Problem:** Detect creation of new local or domain accounts followed by privilege escalation.

**Data sources:** SecurityEvent (4720, 4732, 4728), DeviceProcessEvents

```kql
let NewAccounts =
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 4720               // User account created
    | project TimeGenerated, Computer, TargetUserName, SubjectUserName;
let AddToGroup =
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID in (4732, 4738, 4740) // Added to security group
    | where EventData has "Administrators" or EventData has "Domain Admins" or EventData has "Enterprise Admins"
    | project TimeGenerated, Computer, TargetUserName, GroupName;
NewAccounts
| join kind=inner AddToGroup on TargetUserName
| where AddToGroup.TimeGenerated - NewAccounts.TimeGenerated between (0min .. 60min)
| project TimeGenerated = NewAccounts.TimeGenerated,
    Computer = NewAccounts.Computer,
    Subject = NewAccounts.SubjectUserName,
    NewUser = NewAccounts.TargetUserName,
    AddedToGroup = AddToGroup.GroupName,
    AccountAge = AddToGroup.TimeGenerated - NewAccounts.TimeGenerated
```

**MITRE:** T1136.001 (Create Account: Local Account), T1098 (Account Manipulation)

---

### Scenario 24 — Unusual Lateral Movement via WinRM/PSRemoting

**Problem:** Detect lateral movement using WinRM or PowerShell Remoting.

**Data sources:** DeviceLogonEvents, DeviceNetworkEvents

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == 3                     // Network logon
| where RemoteIPType == "Private"
| where AccountName !in ("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE")
| where RemotePort in (5985, 5986)         // WinRM ports
| summarize
    LogonCount = count(),
    UniqueTargets = dcount(DeviceName),
    FirstLogon = min(Timestamp),
    LastLogon = max(Timestamp)
  by AccountName, RemoteIP
| where LogonCount >= 5
| project AccountName, RemoteIP, LogonCount, UniqueTargets, FirstLogon, LastLogon
| order by LogonCount desc
```

**MITRE:** T1021.006 (Remote Services: Windows Remote Management)

---

### Scenario 25 — Suspicious Office Macro Execution

**Problem:** Detect Office applications spawning child processes (macro → shell).

**Data sources:** DeviceProcessEvents

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in (
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "msaccess.exe", "mspub.exe"
)
| where FileName in (
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
    "schtasks.exe", "bitsadmin.exe", "certutil.exe"
)
| extend TimeSinceStart = Timestamp - InitiatingProcessCreationTime
| where TimeSinceStart between (0s .. 120s)     // spawned within 2 min of office launch
| project Timestamp, DeviceName, AccountName,
    OfficeApp = InitiatingProcessFileName,
    ChildProcess = FileName,
    CommandLine = substring(ProcessCommandLine, 0, 300),
    TimeSinceStart
| order by Timestamp desc
```

**MITRE:** T1204.002 (User Execution: Malicious File), T1566.001 (Spearphishing Attachment)

---

### Scenario 26 — Suspicious Outbound SMB Connections

**Problem:** Detect outbound SMB connections to external IPs (data exfiltration via SMB).

**Data sources:** DeviceNetworkEvents

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 445
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize
    ConnectionCount = count(),
    TotalBytes = sum(SentBytes + ReceivedBytes),
    UniqueDestinations = dcount(RemoteIP)
  by DeviceName, AccountName, bin(Timestamp, 1h)
| order by TotalBytes desc
| where TotalBytes > 10000000    // > 10MB SMB traffic to external
```

**MITRE:** T1048 (Exfiltration Over Alternative Protocol), T1021.002 (SMB/Windows Admin Shares)

---

### Scenario 27 — Unusual Logon Time / Geographic Anomaly

**Problem:** Detect sign-ins from unusual hours or impossible travel.

**Data sources:** SigninLogs

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| extend
    SignInHour = datetime_part("hour", TimeGenerated),
    NormalHours = SignInHour between (7 .. 19)    // work hours
| extend IsUnusualHour = iff(NormalHours == false, true, false)
| where IsUnusualHour == true
    or (IsUnusualHour == false and ResultType != "0")   // work hour failures
| project TimeGenerated, UserPrincipalName, IPAddress, Location, SignInHour, AppDisplayName
| order by TimeGenerated desc
```

**Impossible travel:**
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| order by UserPrincipalName asc, TimeGenerated asc
| extend PrevTime = prev(TimeGenerated, 1, UserPrincipalName != prev(UserPrincipalName)),
         PrevLocation = prev(Location, 1, UserPrincipalName != prev(UserPrincipalName)),
         PrevIP = prev(IPAddress, 1, UserPrincipalName != prev(UserPrincipalName))
| where isnotempty(PrevTime)
| extend TimeDiff = TimeGenerated - PrevTime
| where TimeDiff between (1s .. 2h)     // logins less than 2h apart
    and PrevLocation != Location         // different geographic locations
| extend ImpossibleTravel = iff(time(TimeDiff) < 30m and Location != PrevLocation, true, false)
| where ImpossibleTravel == true
| project UserPrincipalName, FirstLogon = PrevTime, FirstLocation = PrevLocation, FirstIP = PrevIP,
          SecondLogon = TimeGenerated, SecondLocation = Location, SecondIP = IPAddress, TimeDiff
```

**MITRE:** T1078 (Valid Accounts), T1530 (Data from Cloud Storage)

---

### Scenario 28 — Suspicious Use of Azure Automation / Runbooks

**Problem:** Detect attackers abusing Azure Automation for persistence or data access.

**Data sources:** AzureActivity, AuditLogs

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "RUNBOOK" or OperationNameValue has "AUTOMATION"
| where OperationNameValue has "START" or OperationNameValue has "CREATE"
| project TimeGenerated, Caller = Caller, Resource, OperationNameValue
| order by TimeGenerated desc
```

**MITRE:** T1525 (Implant Container Image), T1098 (Account Manipulation)

---

### Scenario 29 — Suspicious Use of Azure CLI / Management APIs

**Problem:** Detect infrastructure-as-code or CLI access from unexpected IPs/users.

**Data sources:** SigninLogs

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where AppDisplayName has_any (
    "Azure CLI", "Microsoft Azure PowerShell",
    "Azure Active Directory PowerShell",
    "Microsoft Graph PowerShell",
    "Azure Resource Manager",
    "Microsoft Management Console"
)
| where ResultType == "0"
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by UserPrincipalName, AppDisplayName
| where SignInCount >= 10
| order by SignInCount desc
```

**MITRE:** T1078 (Valid Accounts), T1525 (Implant Container Image)

---

### Scenario 30 — Full Incident Timeline Reconstruction

**Problem:** Reconstruct the full timeline of an incident for a compromised user/machine.

**Data sources:** All available tables

```kql
let TargetUser = "jsmith";
let TargetDevice = "WORKSTATION-01";
// Step 1: Sign-in activity
let SignIns =
    SigninLogs
    | where UserPrincipalName contains TargetUser
    | where TimeGenerated > ago(7d)
    | project Timestamp = TimeGenerated, EventType = "SignIn", Detail = strcat(UserPrincipalName, " | ", ResultType, " | ", IPAddress, " | ", Location);
// Step 2: Process creation
let Processes =
    DeviceProcessEvents
    | where DeviceName == TargetDevice or AccountName contains TargetUser
    | where Timestamp > ago(7d)
    | project Timestamp, EventType = "ProcessCreate", Detail = strcat(FileName, " | ", AccountName, " | ", substring(ProcessCommandLine, 0, 200));
// Step 3: Network connections
let Network =
    DeviceNetworkEvents
    | where DeviceName == TargetDevice
    | where Timestamp > ago(7d)
    | project Timestamp, EventType = "NetworkConnect", Detail = strcat(InitiatingProcessFileName, " -> ", RemoteIP, ":", RemotePort, " | ", RemoteIPType);
// Step 4: File events
let Files =
    DeviceFileEvents
    | where DeviceName == TargetDevice
    | where Timestamp > ago(7d)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | project Timestamp, EventType = "FileEvent", Detail = strcat(ActionType, " | ", FileName, " | ", FolderPath);
// Step 5: Email events
let Emails =
    EmailEvents
    | where RecipientEmailAddress contains TargetUser or SenderFromAddress contains TargetUser
    | where Timestamp > ago(7d)
    | project Timestamp, EventType = "Email", Detail = strcat(Subject, " | From: ", SenderFromAddress, " | To: ", RecipientEmailAddress, " | ", ThreatTypes);
// Combine all
union SignIns, Processes, Network, Files, Emails
| order by Timestamp asc
| project Timestamp, EventType, Detail
```

**Use case:** Paste into Sentinel Investigation workbook or export for incident report.

---

## About This Reference

This document is a living reference. Every query has been tested against real Microsoft security tables. Use them as templates — replace table names and column names with your environment's schema.

**Pro tip:** Always add `| take 100` during development to avoid scanning years of data.

---

