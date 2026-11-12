# Edge: what stands between the internet and the apps. WAF on CloudFront and internet-facing load
# balancers, CloudFront's TLS and origins (and whether its WAF can be bypassed), load balancer
# listeners and attributes, ACM certificates (expiring, stuck renewing, unused).
include "posture";

. as $in
| ($in.vpcs.Vpcs // [] | map({key: .VpcId, value: tagv($cfg; .Tags)}) | from_entries) as $vpc_env
| ($in.lb_detail | map({key: .arn, value: .}) | from_entries) as $lbd
| ([$in.waf[] | .resources[]] | unique) as $waf_lbs
| ($in.cf.DistributionList.Items // []) as $dists
| ([$dists[] | .Origins.Items[]? | .DomainName | ascii_downcase]) as $cf_origins
| ($in.sgs.SecurityGroups // [] | map({key: .GroupId, value: .}) | from_entries) as $sg
| def base($what; $diag): {area: "edge", resource: "\($in.label)/\($in.region)/\($what)", link: "", evidence: {}} + (if $diag then {diag: $diag} else {} end);
  def lbdiag($lb): {type: "lb", profile: $in.label, region: $in.region, id: $lb.LoadBalancerName};
  def open_to_world($ids): [$ids[]? | $sg[.] // empty | .IpPermissions[]? | (.IpRanges[]?.CidrIp, .Ipv6Ranges[]?.CidrIpv6) | select(. == "0.0.0.0/0" or . == "::/0")] | length > 0;
  def old_tls: test("2016-08|TLS-1-0|TLS-1-1|2015-05|2015-03|2015-02|2014-10|2014-01|2011-08|FS-2018-06$|FS-1-1"; "i");
(
  # --- internet-facing load balancers ---------------------------------------------------------
  ( $in.lbs.LoadBalancers // [] | .[] | select(.Scheme == "internet-facing") | . as $lb
    | ($lbd[$lb.LoadBalancerArn] // {listeners: [], attrs: {}, tags: []}) as $d
    | env_of($cfg; $d.tags; $vpc_env[$lb.VpcId // ""]; $lb.LoadBalancerName) as $e
    | (($cf_origins | index($lb.DNSName | ascii_downcase)) != null) as $behind_cf
    | select(listed($cfg; $lb.LoadBalancerName) | not)
    | (
      # WAF: an ALB the internet reaches directly should have a web ACL (unless CloudFront fronts it).
      (select($lb.Type == "application" and ($waf_lbs | index($lb.LoadBalancerArn)) == null and ($behind_cf | not))
       | base("lb/\($lb.LoadBalancerName)"; lbdiag($lb)) + {check: "edge.alb_no_waf", severity: (if is_prd($cfg; $e) then "warning" else "info" end),
           message: "Internet-facing ALB \($lb.LoadBalancerName) (\($e // "untagged")) has no WAF web ACL, so nothing filters requests before they reach the apps",
           fix: "Attach a WAFv2 web ACL in Terraform (aws_wafv2_web_acl_association) with at least the AWS managed Common, KnownBadInputs and IP reputation rule groups."}),
      # Behind CloudFront but still open to the world: CloudFront's WAF can be skipped.
      (select($behind_cf and open_to_world($lb.SecurityGroups))
       | base("lb/\($lb.LoadBalancerName)"; lbdiag($lb)) + {check: "edge.cf_origin_bypass", severity: "warning",
           message: "ALB \($lb.LoadBalancerName) is a CloudFront origin but its security group allows 0.0.0.0/0, so anyone can skip CloudFront (and its WAF) by calling the ALB directly",
           fix: "Allow only CloudFront's managed prefix list (com.amazonaws.global.cloudfront.origin-facing) on the ALB's security group, and have CloudFront send a secret header the ALB's listener rule requires."}),
      # Listeners: plain HTTP that doesn't redirect, and old TLS policies.
      ($d.listeners[] | select(.Protocol == "HTTP" and ([.DefaultActions[]?.Type] | index("redirect") | not))
       | base("lb/\($lb.LoadBalancerName)"; lbdiag($lb)) + {check: "edge.http_not_redirected", severity: (if is_prd($cfg; $e) then "warning" else "info" end),
           message: "\($lb.LoadBalancerName) serves plain HTTP on port \(.Port) instead of redirecting to HTTPS",
           fix: "Make the HTTP listener's default action a redirect to HTTPS (status 301) in Terraform."}),
      ($d.listeners[] | select((.Protocol == "HTTPS" or .Protocol == "TLS") and ((.SslPolicy // "") | old_tls))
       | base("lb/\($lb.LoadBalancerName)"; lbdiag($lb)) + {check: "edge.old_tls_policy", severity: "warning",
           message: "\($lb.LoadBalancerName) port \(.Port) uses TLS policy \(.SslPolicy), which allows TLS 1.0 or 1.1",
           fix: "Use ELBSecurityPolicy-TLS13-1-2-2021-06 (TLS 1.2 and 1.3) as the listener's ssl_policy."}),
      # Attributes.
      (select(is_prd($cfg; $e) and ($d.attrs["deletion_protection.enabled"] // "false") == "false")
       | base("lb/\($lb.LoadBalancerName)"; lbdiag($lb)) + {check: "edge.lb_no_deletion_protection", severity: "info",
           message: "Production load balancer \($lb.LoadBalancerName) can be deleted without turning off deletion protection first",
           fix: "Set enable_deletion_protection = true on it in Terraform."}),
      (select($lb.Type == "application" and ($d.attrs["routing.http.drop_invalid_header_fields.enabled"] // "false") == "false")
       | base("lb/\($lb.LoadBalancerName)"; lbdiag($lb)) + {check: "edge.lb_keeps_invalid_headers", severity: "info",
           message: "ALB \($lb.LoadBalancerName) passes malformed HTTP headers through to the apps",
           fix: "Set drop_invalid_header_fields = true (it blocks a class of request smuggling)."}),
      (select(is_prd($cfg; $e) and ($d.attrs["access_logs.s3.enabled"] // "false") == "false")
       | base("lb/\($lb.LoadBalancerName)"; lbdiag($lb)) + {check: "edge.lb_no_access_logs", severity: "info",
           message: "Production load balancer \($lb.LoadBalancerName) keeps no access logs, so there's no record of who called what",
           fix: "Turn on access_logs to an S3 bucket in Terraform."})
    )),

  # --- regional WAF web ACLs ------------------------------------------------------------------
  ( $in.waf[] | . as $acl
    | base("waf/\($acl.Name)"; null) as $b
    | (
      ([$acl.Rules[]? | select((.Action.Count != null) or (.OverrideAction.Count != null)) | .Name]) as $counting
      | (select(($counting | length) > 0)
         | $b + {check: "edge.waf_count_only", severity: "warning",
             message: "WAF \($acl.Name) has \(plural($counting | length; "rule"; "rules")) only counting, not blocking: \($counting | names(5))",
             fix: "If they were left in count mode after testing, switch them to block (override_action none, or the rule's action)."}),
      (select(($acl.resources | length) == 0)
       | $b + {check: "edge.waf_unattached", severity: "info", message: "WAF \($acl.Name) isn't attached to any load balancer",
           fix: "Attach it, or delete it if it's left over."}),
      (select($acl.logging | not)
       | $b + {check: "edge.waf_no_logging", severity: "info", message: "WAF \($acl.Name) doesn't log, so blocked requests can't be investigated",
           fix: "Add an aws_wafv2_web_acl_logging_configuration (to CloudWatch Logs, S3 or Firehose)."}),
      (select(([$acl.Rules[]? | .Statement.ManagedRuleGroupStatement.Name // empty] | index("AWSManagedRulesCommonRuleSet")) == null)
       | $b + {check: "edge.waf_no_common_rules", severity: "info", message: "WAF \($acl.Name) doesn't use the AWS managed Common rule set",
           fix: "Add AWSManagedRulesCommonRuleSet (and KnownBadInputs, AmazonIpReputationList)."})
    )),

  # --- ACM certificates -----------------------------------------------------------------------
  ( $in.acm[] | . as $c
    | days_left($in.now; $c.NotAfter) as $left
    | base("acm/\($c.DomainName)"; {type: "acm", profile: $in.label, region: $in.region, id: $c.CertificateArn}) as $b
    | (
      (select($c.Status == "EXPIRED" or ($left != null and $left < 0))
       | $b + {check: "edge.cert_expired", severity: (if ($c.InUseBy | length) > 0 then "critical" else "info" end),
           message: "Certificate for \($c.DomainName) expired \($c.NotAfter[0:10])\(if ($c.InUseBy | length) > 0 then " and is still in use by \($c.InUseBy | map(split("/") | .[-2] // .) | names(3))" else "" end)",
           fix: (if $c.Type == "IMPORTED" then "Import a renewed certificate (ACM can't renew imported ones), or switch to an ACM-issued certificate." else "Request a new certificate and move the listeners to it." end)}),
      (select($c.Status == "ISSUED" and $left != null and $left >= 0 and $left <= ($cfg.cert_warn_days * 2) and ($c.Type == "IMPORTED" or (($c.RenewalSummary.RenewalStatus // "") | IN("PENDING_VALIDATION", "FAILED")) or ($c.RenewalEligibility == "INELIGIBLE")))
       | ([$c.RenewalSummary.DomainValidationOptions[]?, $c.DomainValidationOptions[]? | select(.ValidationStatus != "SUCCESS") | .ResourceRecord // empty] | unique) as $records
       | $b + {check: "edge.cert_not_renewing", severity: (if $left <= $cfg.cert_warn_days then "error" else "warning" end),
           message: "Certificate for \($c.DomainName) expires \($c.NotAfter[0:10]) (\($left) days) and \(if $c.Type == "IMPORTED" then "is imported, so ACM won't renew it" elif ($c.RenewalSummary.RenewalStatus // "") == "FAILED" then "its renewal failed: \($c.RenewalSummary.RenewalStatusReason // "no reason given")" elif $c.RenewalEligibility == "INELIGIBLE" then "isn't eligible for renewal (it isn't in use, or its validation records are gone)" else "renewal is waiting on DNS validation" end)",
           fix: (if ($records | length) > 0 then "Add (or restore) these DNS validation records in the dns repo: \($records | map("\(.Name) \(.Type) \(.Value)") | join("; "))" elif $c.Type == "IMPORTED" then "Import a renewed certificate before then." else "Make sure the domain's CNAME validation records still exist and the certificate is attached to something." end),
           evidence: {records: $records}}),
      (select($c.Status == "ISSUED" and ($c.InUseBy | length) == 0 and $c.Type != "IMPORTED")
       | $b + {check: "edge.cert_unused", severity: "info", message: "Certificate for \($c.DomainName) isn't attached to anything, so ACM won't renew it",
           fix: "Delete it if it's left over; if it's meant for something, attach it before it expires (\($c.NotAfter[0:10]))."})
    )),

  # --- CloudFront (account-wide, so only with the first region) --------------------------------
  ( select($in.first) | $dists[] | . as $d
    | ($d.Aliases.Items[0] // $d.DomainName) as $name
    | base("cloudfront/\($name)"; {type: "cloudfront", profile: $in.label, id: $d.Id}) as $b
    | ($name | env_from_name) as $e
    | select(listed($cfg; $d.Id) | not)
    | (
      (select(($d.WebACLId // "") == "")
       | $b + {check: "edge.cf_no_waf", severity: (if is_prd($cfg; $e) or $e == null then "warning" else "info" end),
           message: "CloudFront distribution \($name) (\($d.Id)) has no WAF web ACL",
           fix: "Attach a WAFv2 web ACL with scope CLOUDFRONT (created in us-east-1) via web_acl_id in Terraform."}),
      (select([$d.DefaultCacheBehavior, ($d.CacheBehaviors.Items[]?)] | any(.ViewerProtocolPolicy == "allow-all"))
       | $b + {check: "edge.cf_allows_http", severity: "warning", message: "CloudFront \($name) serves plain HTTP to viewers",
           fix: "Set viewer_protocol_policy = redirect-to-https on every cache behavior."}),
      (select(($d.ViewerCertificate.CloudFrontDefaultCertificate // false | not) and (($d.ViewerCertificate.MinimumProtocolVersion // "") | IN("TLSv1.2_2021", "TLSv1.2_2019", "TLSv1.2_2018") | not))
       | $b + {check: "edge.cf_old_tls", severity: "warning",
           message: "CloudFront \($name) accepts \($d.ViewerCertificate.MinimumProtocolVersion // "old TLS versions")",
           fix: "Set minimum_protocol_version = TLSv1.2_2021."}),
      ($d.Origins.Items[]? | select((.DomainName | test("\\.s3[.-]")) and (.S3OriginConfig != null) and ((.OriginAccessControlId // "") == "") and ((.S3OriginConfig.OriginAccessIdentity // "") == ""))
       | $b + {check: "edge.cf_s3_origin_public", severity: "warning",
           message: "CloudFront \($name) reads S3 origin \(.DomainName) without origin access control, so the bucket must be readable by anyone",
           fix: "Add an origin access control (aws_cloudfront_origin_access_control) and a bucket policy that allows only this distribution; then block public access on the bucket."}),
      ($d.Origins.Items[]? | select(.CustomOriginConfig.OriginProtocolPolicy == "http-only" and (.DomainName | test("elb\\.amazonaws\\.com$")))
       | $b + {check: "edge.cf_origin_http", severity: "warning",
           message: "CloudFront \($name) talks to its load balancer origin \(.DomainName) over plain HTTP",
           fix: "Set origin_protocol_policy = https-only and give the ALB an HTTPS listener."})
    )),

  # --- CloudFront's WAF ACLs (account-wide) ----------------------------------------------------
  ( select($in.first) | $in.waf_cf[] | . as $acl
    | ([$acl.Rules[]? | select((.Action.Count != null) or (.OverrideAction.Count != null)) | .Name]) as $counting
    | select(($counting | length) > 0)
    | base("waf/\($acl.Name)"; null) + {check: "edge.waf_count_only", severity: "warning",
        message: "CloudFront WAF \($acl.Name) has \(plural($counting | length; "rule"; "rules")) only counting, not blocking: \($counting | names(5))",
        fix: "If they were left in count mode after testing, switch them to block."})
)
