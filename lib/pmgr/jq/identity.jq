# Identity: who can become what. Trust policies (GitHub OIDC not pinned to a repo, EKS IRSA with
# wildcards, any principal, unknown accounts without an ExternalId), admin and PassRole-on-* policies,
# unused roles, IAM users (old or unused keys, console without MFA), the root user, and the account
# baseline (CloudTrail logging, GuardDuty, EBS encryption by default).
include "posture";

. as $in
| def base($what; $diag): {area: "identity", resource: "\($in.label)/\($what)", link: "", evidence: {}} + (if $diag then {diag: $diag} else {} end);
  def as_list: if type == "array" then . elif . == null then [] else [.] end;
  def statements: (.Statement // []) | as_list;
  # Condition values for keys matching a pattern, across every operator.
  def cond_values($pat): [(.Condition // {}) | to_entries[] | .value | to_entries[] | select(.key | test($pat; "i")) | .value | as_list[]];
  def aws_managed_role: (.Path // "/" | startswith("/aws-service-role/") or startswith("/aws-reserved/")) or (.RoleName | startswith("AWSReservedSSO_"));
  def account_of: tostring | capture("(?<a>[0-9]{12})").a // null;
  def allows_all: (.Effect == "Allow") and ((.Action | as_list) | index("*")) != null and ((.Resource | as_list) | index("*")) != null;
  def passrole_star: (.Effect == "Allow") and ((.Action | as_list) | any(. == "iam:PassRole" or . == "iam:*" )) and ((.Resource | as_list) | index("*")) != null;
  ([$in.account] + ($cfg.trusted_accounts // []) | map(tostring)) as $ours
  | ($in.iam.Policies // [] | map({key: .Arn, value: ([.PolicyVersionList[]? | select(.IsDefaultVersion) | .Document] | first)}) | from_entries) as $local
| (
  # Account-wide (IAM is global): only with the first region.
  (select($in.first) | (
  # --- roles ----------------------------------------------------------------------------------
  ( $in.iam.RoleDetailList // [] | .[] | . as $r
    | select(aws_managed_role | not) | select(listed($cfg; $r.RoleName) | not)
    | base("role/\($r.RoleName)"; {type: "iam_role", profile: $in.label, id: $r.RoleName}) as $b
    | ($r.AssumeRolePolicyDocument | if type == "string" then (fromjson? // {}) else . end) as $trust
    | (
      # GitHub Actions OIDC: the sub claim must pin the repo (and ideally the branch or environment).
      ($trust | statements[] | select(.Effect == "Allow") | select(((.Principal.Federated // "") | as_list) | any(test("token.actions.githubusercontent.com")))
       | cond_values("token.actions.githubusercontent.com:sub") as $subs
       | if ($subs | length) == 0 then
           $b + {check: "identity.github_oidc_unpinned", severity: "critical",
             message: "Role \($r.RoleName) trusts GitHub Actions with no sub condition, so a workflow in any GitHub repository, anyone's, can assume it",
             fix: "Add a StringLike condition on token.actions.githubusercontent.com:sub, such as repo:YOUR_ORG/platform-infra:ref:refs/heads/main or repo:YOUR_ORG/platform-infra:environment:prd."}
         elif ($subs | any(. == "*" or test("^repo:\\*") or test("^\\*"))) then
           $b + {check: "identity.github_oidc_unpinned", severity: "critical",
             message: "Role \($r.RoleName) trusts GitHub Actions with sub \($subs | join(", ")), which matches any repository",
             fix: "Pin the sub condition to your organization and repository: repo:YOUR_ORG/REPO:ref:refs/heads/main (or :environment:NAME)."}
         elif ($subs | any(test("^repo:[^/]+/\\*"))) then
           $b + {check: "identity.github_oidc_org_wide", severity: "warning",
             message: "Role \($r.RoleName) can be assumed by any repository in \($subs | map(capture("^repo:(?<o>[^/]+)/").o) | unique | join(", ")) (sub \($subs | join(", ")))",
             fix: "Limit it to the repositories (and branches or environments) that need it, so a workflow in an unrelated repo can't use it."}
         elif ($subs | any(test(":\\*$") and (test(":ref:|:environment:") | not))) then
           $b + {check: "identity.github_oidc_any_ref", severity: "info",
             message: "Role \($r.RoleName) can be assumed from any branch or pull request of \($subs | map(capture("^repo:(?<r>[^:]+)").r) | unique | join(", "))",
             fix: "If it can change infrastructure, pin it to the main branch or a protected environment (repo:ORG/REPO:environment:prd)."}
         else empty end),
      # EKS IRSA: the sub must name a service account.
      ($trust | statements[] | select(.Effect == "Allow") | select(((.Principal.Federated // "") | as_list) | any(test("oidc.eks.")))
       | cond_values(":sub$") as $subs
       | select(($subs | length) == 0 or ($subs | any(test("^system:serviceaccount:\\*|^\\*$|:\\*$"))))
       | $b + {check: "identity.irsa_wildcard", severity: "warning",
           message: "Role \($r.RoleName) can be assumed by \(if ($subs | length) == 0 then "any service account in the cluster" else "service accounts matching \($subs | join(", "))" end)",
           fix: "Set the trust condition to the exact service account: StringEquals <issuer>:sub = system:serviceaccount:NAMESPACE:NAME (and :aud = sts.amazonaws.com)."}),
      # Anyone, or an account we don't know without an ExternalId.
      ($trust | statements[] | select(.Effect == "Allow") | . as $st
       | ((.Principal.AWS // empty) | as_list[]) as $p
       | if ($p == "*") and ((.Condition // {}) | length) == 0 then
           $b + {check: "identity.trust_anyone", severity: "critical", message: "Role \($r.RoleName) can be assumed by any AWS principal in any account",
             fix: "Replace Principal \"*\" with the accounts or roles that need it."}
         elif ($p | account_of) as $a | $a != null and ($ours | index($a)) == null and (($st | cond_values("sts:ExternalId")) | length) == 0 then
           $b + {check: "identity.trust_unknown_account", severity: "warning",
             message: "Role \($r.RoleName) trusts account \($p | account_of), which isn't one of yours, with no ExternalId",
             fix: "If it's a vendor, require an sts:ExternalId they give you (it stops the confused-deputy problem). If it's yours, add it to posture.trusted_accounts."}
         else empty end),
      # Too much power.
      ([$r.AttachedManagedPolicies[]? | select(.PolicyArn | endswith(":policy/AdministratorAccess"))] | length > 0) as $admin
      | ([$r.RolePolicyList[]? | .PolicyDocument | if type == "string" then (fromjson? // {}) else . end | statements[]]
         + [$r.AttachedManagedPolicies[]? | $local[.PolicyArn] // empty | statements[]]) as $stmts
      | (select($admin or ($stmts | any(allows_all)))
         | $b + {check: "identity.role_admin", severity: "info",
             message: "Role \($r.RoleName) can do anything (\(if $admin then "AdministratorAccess" else "a policy allowing * on *" end))",
             fix: "If a pipeline or app assumes it, scope it to the services and resources it changes. Admin roles belong to people, through SSO."}),
      (select(($admin | not) and ($stmts | any(passrole_star)))
       | $b + {check: "identity.passrole_any", severity: "warning",
           message: "Role \($r.RoleName) can pass any role to a service, so it can hand itself (or a Lambda or EC2 instance it creates) any role's permissions",
           fix: "Limit iam:PassRole to the specific role ARNs it needs, with an iam:PassedToService condition."}),
      # Unused.
      (days_ago($in.now; $r.RoleLastUsed.LastUsedDate // null) as $since
       | days_ago($in.now; $r.CreateDate) as $age
       | select(($age // 0) > $cfg.unused_days and (($since == null) or ($since > $cfg.unused_days)))
       | $b + {check: "identity.role_unused", severity: "info",
           message: "Role \($r.RoleName) \(if $since == null then "has never been used" else "hasn't been used in \($since) days" end) (created \($age) days ago)",
           fix: "Delete it if nothing needs it; unused roles with permissions are risk with no benefit."})
    )),

  # --- IAM users ------------------------------------------------------------------------------
  ( $in.users[] | . as $u
    | base("user/\($u.user)"; {type: "iam_user", profile: $in.label, id: $u.user}) as $b
    | select(listed($cfg; $u.user) | not)
    | (
      (select($u.console and (($u.mfa // [1]) | length) == 0)
       | $b + {check: "identity.user_no_mfa", severity: "error", message: "IAM user \($u.user) can sign in to the console without MFA",
           fix: "Move them to SSO; if they must stay an IAM user, require an MFA device."}),
      ($u.keys[] | select(.Status == "Active") | . as $k
       | days_ago($in.now; $k.CreateDate) as $age
       | ([$u.last_used[] | .at] | map(select(. != null)) | sort | last) as $used
       | days_ago($in.now; $used) as $idle
       | (select($age > $cfg.key_age_days)
          | $b + {check: "identity.access_key_old", severity: "warning",
              message: "IAM user \($u.user)'s access key \($k.AccessKeyId[0:8])… is \($age) days old\(if $idle == null then " and has never been used" elif $idle > $cfg.unused_days then " and unused for \($idle) days" else "" end)",
              fix: (if $idle == null or $idle > $cfg.unused_days then "Deactivate it, then delete it." else "Rotate it, or better, replace it with a role (OIDC for CI, IRSA or Pod Identity in clusters)." end)}))
    )),

  # --- root and the account baseline ----------------------------------------------------------
  ( $in.summary.SummaryMap // {} | . as $s
    | base("account"; null) as $b
    | (select(($s.AccountAccessKeysPresent // 0) > 0)
       | $b + {check: "identity.root_access_keys", severity: "critical", message: "The root user of \($in.label) has access keys",
           fix: "Delete them (IAM console as root, Security credentials). Nothing should run as root."}),
      (select(($s.AccountMFAEnabled // 1) == 0)
       | $b + {check: "identity.root_no_mfa", severity: "error", message: "The root user of \($in.label) has no MFA",
           fix: "Add a hardware or passkey MFA to the root user."})),
  ( select($in.trails != null)
    | ([$in.trail_status[] | select(.IsLogging)] | length) as $logging
    | select($logging == 0)
    | base("account"; null) + {check: "identity.no_cloudtrail", severity: "error",
        message: "\($in.label) has no multi-region CloudTrail trail that's logging, so there's no record of who changed what",
        fix: "Create an organization trail (or a multi-region trail) to S3, with log file validation on."})
  )),

  # --- per region: GuardDuty and EBS encryption by default -----------------------------------
  ( select($in.guardduty != null) | select(($in.guardduty.DetectorIds // []) | length == 0 or ($in.gd_detector.Status // "ENABLED") != "ENABLED")
    | base("\($in.region)/guardduty"; null) + {check: "identity.no_guardduty", severity: "warning",
        message: "GuardDuty isn't on in \($in.label) \($in.region), so nothing watches for compromised credentials, crypto-mining or unusual API calls",
        fix: "Enable GuardDuty (organization-wide from the delegated admin account is simplest)."}),
  ( select($in.ebs_default != null and ($in.ebs_default.EbsEncryptionByDefault // true | not))
    | base("\($in.region)/ebs-default"; null) + {check: "identity.ebs_not_encrypted_by_default", severity: "info",
        message: "New EBS volumes in \($in.label) \($in.region) aren't encrypted unless someone asks",
        fix: "Turn on EBS encryption by default for the region (aws_ebs_encryption_by_default)."})
)
