# Data: S3 buckets (public, TLS, versioning, lifecycle), RDS and Aurora (encryption, IAM auth,
# backups, Multi-AZ, deletion protection, CA certificates, managed passwords), Redshift (encryption,
# require_ssl, audit logs, VPC routing, snapshots), ElastiCache (encryption, AUTH, failover,
# backups), Secrets Manager (rotation that isn't happening, secrets nobody reads).
include "posture";

. as $in
| ($in.vpcs.Vpcs // [] | map({key: .VpcId, value: tagv($cfg; .Tags)}) | from_entries) as $vpc_env
| def base($what; $diag): {area: "data", resource: "\($in.label)/\($in.region)/\($what)", link: "", evidence: {}} + (if $diag then {diag: $diag} else {} end);
  def statements: (.Statement // []) | if type == "array" then . else [.] end;
  def as_list: if type == "array" then . elif . == null then [] else [.] end;
(
  # --- S3 (account-wide: with the first region) -----------------------------------------------
  ( select($in.first) | $in.buckets[] | . as $bk
    | env_of($cfg; $bk.tags; null; $bk.name) as $e
    | {area: "data", resource: "\($in.label)/s3/\($bk.name)", link: "", evidence: {}, diag: {type: "s3", profile: $in.label, region: $bk.region, id: $bk.name}} as $b
    | select(listed($cfg; $bk.name) | not)
    | ([$bk.grants[] | select(.Grantee.URI // "" | test("AllUsers|AuthenticatedUsers")) | .Permission]) as $acl_public
    | (
      (select($bk.public or ($acl_public | length) > 0)
       | $b + {check: "data.s3_public", severity: "error",
           message: "Bucket \($bk.name) is public\(if $bk.public then " (AWS evaluates its bucket policy as public)" else "" end)\(if ($acl_public | length) > 0 then " (its ACL grants \($acl_public | unique | join(", ")) to everyone)" else "" end)",
           fix: "If CloudFront serves it, use origin access control and a policy that allows only the distribution. Otherwise remove the public statement or ACL grant, then turn on Block Public Access for the bucket. If it's meant to be public, add it to posture.ignore."}),
      (select($bk.policy_read and ($bk.policy == null or ([$bk.policy | statements[] | select(.Effect == "Deny" and ((.Condition.Bool["aws:SecureTransport"] // .Condition.Bool["aws:securetransport"] // null) | tostring | low) == "false")] | length) == 0))
       | $b + {check: "data.s3_no_tls_required", severity: "info", message: "Bucket \($bk.name) accepts requests over plain HTTP",
           fix: "Add a bucket policy statement that denies s3:* when aws:SecureTransport is false."}),
      (select(is_prd($cfg; $e) and $bk.versioning != "Enabled")
       | $b + {check: "data.s3_no_versioning", severity: "warning",
           message: "Production bucket \($bk.name) doesn't keep versions, so an overwrite or delete can't be undone",
           fix: "Enable versioning (aws_s3_bucket_versioning), with a lifecycle rule that expires old versions."}),
      (select($bk.lifecycle != null and ($bk.lifecycle | length) == 0)
       | $b + {check: "data.s3_no_lifecycle", severity: "info",
           message: "Bucket \($bk.name) has no lifecycle rules, so objects (and old versions, and failed multipart uploads) are kept, and billed, forever",
           fix: "Add an aws_s3_bucket_lifecycle_configuration: abort incomplete multipart uploads after 7 days, expire noncurrent versions, and move cold data to a cheaper storage class."})
    )),

  # --- RDS instances (not Aurora members; their cluster is checked below) ----------------------
  ( $in.rds.DBInstances // [] | .[] | select(.DBClusterIdentifier == null) | . as $db
    | env_of($cfg; $db.TagList; $vpc_env[$db.DBSubnetGroup.VpcId // ""]; $db.DBInstanceIdentifier) as $e
    | base("rds/\($db.DBInstanceIdentifier)"; {type: "rds", profile: $in.label, region: $in.region, id: $db.DBInstanceIdentifier}) as $b
    | select(listed($cfg; $db.DBInstanceIdentifier) | not)
    | (
      (select($db.StorageEncrypted | not)
       | $b + {check: "data.rds_unencrypted", severity: "error", message: "RDS instance \($db.DBInstanceIdentifier) stores its data unencrypted",
           fix: "Encryption can't be turned on in place: snapshot it, copy the snapshot with a KMS key, and restore from the encrypted copy."}),
      (select(($db.IAMDatabaseAuthenticationEnabled // false) | not)
       | $b + {check: "data.rds_no_iam_auth", severity: "info",
           message: "RDS instance \($db.DBInstanceIdentifier) doesn't allow IAM authentication, so every app uses a long-lived database password",
           fix: "Set iam_database_authentication_enabled = true, then let apps (via IRSA or Pod Identity) connect with rds-db:connect tokens."}),
      (select(($db.BackupRetentionPeriod // 0) < 7)
       | $b + {check: "data.rds_short_backups", severity: (if ($db.BackupRetentionPeriod // 0) == 0 then "error" else "warning" end),
           message: "RDS instance \($db.DBInstanceIdentifier) keeps \(if ($db.BackupRetentionPeriod // 0) == 0 then "no automated backups" else "automated backups for only \($db.BackupRetentionPeriod) days" end)",
           fix: "Set backup_retention_period to at least 7 (14 to 35 for production)."}),
      (select(is_prd($cfg; $e) and ($db.DeletionProtection | not))
       | $b + {check: "data.rds_no_deletion_protection", severity: "warning", message: "Production database \($db.DBInstanceIdentifier) can be deleted in one call",
           fix: "Set deletion_protection = true."}),
      (select(is_prd($cfg; $e) and ($db.MultiAZ | not))
       | $b + {check: "data.rds_single_az", severity: "warning", message: "Production database \($db.DBInstanceIdentifier) runs in one Availability Zone, so a zone outage takes it down",
           fix: "Set multi_az = true (a short failover replaces long downtime)."}),
      (select(($db.CACertificateIdentifier // "") | test("rds-ca-2019|rds-ca-2015"))
       | $b + {check: "data.rds_old_ca", severity: "error", message: "RDS instance \($db.DBInstanceIdentifier) still uses CA \($db.CACertificateIdentifier), which has expired",
           fix: "Set ca_cert_identifier = rds-ca-rsa2048-g1 (apps that verify the server certificate need the new bundle)."}),
      (select(($db.CertificateDetails.ValidTill // null) != null and days_left($in.now; $db.CertificateDetails.ValidTill) <= 60)
       | $b + {check: "data.rds_cert_expiring", severity: "warning", message: "RDS instance \($db.DBInstanceIdentifier)'s server certificate expires \($db.CertificateDetails.ValidTill[0:10])",
           fix: "Rotate it (modify the instance with the same CA, applying at the next maintenance window)."}),
      (select(($db.MasterUserSecret // null) == null)
       | $b + {check: "data.rds_password_unmanaged", severity: "info",
           message: "RDS instance \($db.DBInstanceIdentifier)'s master password isn't managed by Secrets Manager, so it never rotates",
           fix: "Set manage_master_user_password = true; RDS stores and rotates it in Secrets Manager."})
    )),

  # --- Aurora clusters ------------------------------------------------------------------------
  ( $in.aurora.DBClusters // [] | .[] | select((.Engine // "") | startswith("aurora")) | . as $cl
    | env_of($cfg; $cl.TagList; null; $cl.DBClusterIdentifier) as $e
    | base("aurora/\($cl.DBClusterIdentifier)"; {type: "rds", profile: $in.label, region: $in.region, id: ($cl.DBClusterMembers[0].DBInstanceIdentifier // $cl.DBClusterIdentifier)}) as $b
    | select(listed($cfg; $cl.DBClusterIdentifier) | not)
    | (
      (select($cl.StorageEncrypted | not)
       | $b + {check: "data.rds_unencrypted", severity: "error", message: "Aurora cluster \($cl.DBClusterIdentifier) stores its data unencrypted",
           fix: "Snapshot it, restore the snapshot into a new encrypted cluster, and switch over."}),
      (select(($cl.IAMDatabaseAuthenticationEnabled // false) | not)
       | $b + {check: "data.rds_no_iam_auth", severity: "info", message: "Aurora cluster \($cl.DBClusterIdentifier) doesn't allow IAM authentication",
           fix: "Set iam_database_authentication_enabled = true and use rds-db:connect tokens from the apps' roles."}),
      (select(($cl.BackupRetentionPeriod // 0) < 7)
       | $b + {check: "data.rds_short_backups", severity: "warning", message: "Aurora cluster \($cl.DBClusterIdentifier) keeps backups for only \($cl.BackupRetentionPeriod // 0) days",
           fix: "Set backup_retention_period to at least 7."}),
      (select(is_prd($cfg; $e) and ($cl.DeletionProtection | not))
       | $b + {check: "data.rds_no_deletion_protection", severity: "warning", message: "Production Aurora cluster \($cl.DBClusterIdentifier) can be deleted in one call",
           fix: "Set deletion_protection = true."}),
      (select(is_prd($cfg; $e) and (($cl.DBClusterMembers // []) | length) < 2 and (($cl.EngineMode // "provisioned") != "serverless"))
       | $b + {check: "data.rds_single_az", severity: "warning",
           message: "Production Aurora cluster \($cl.DBClusterIdentifier) has one instance, so a failure means downtime until a new one starts",
           fix: "Add a reader in another Availability Zone; Aurora fails over to it in about 30 seconds."}),
      (select(($cl.MasterUserSecret // null) == null)
       | $b + {check: "data.rds_password_unmanaged", severity: "info", message: "Aurora cluster \($cl.DBClusterIdentifier)'s master password isn't managed by Secrets Manager",
           fix: "Set manage_master_user_password = true."})
    )),

  # --- Redshift -------------------------------------------------------------------------------
  ( $in.redshift.Clusters // [] | .[] | . as $rs
    | (([$in.rs_detail[] | select(.id == $rs.ClusterIdentifier)] | first) // {}) as $x
    | env_of($cfg; $rs.Tags; $vpc_env[$rs.VpcId // ""]; $rs.ClusterIdentifier) as $e
    | base("redshift/\($rs.ClusterIdentifier)"; {type: "redshift", profile: $in.label, region: $in.region, id: $rs.ClusterIdentifier}) as $b
    | select(listed($cfg; $rs.ClusterIdentifier) | not)
    | (
      (select($rs.Encrypted | not)
       | $b + {check: "data.redshift_unencrypted", severity: "error", message: "Redshift cluster \($rs.ClusterIdentifier) stores its data unencrypted",
           fix: "Turn on encryption with a KMS key (Redshift migrates the data; the cluster is read-only meanwhile)."}),
      (select(($x.require_ssl // "true") | low == "false")
       | $b + {check: "data.redshift_no_ssl", severity: "warning", message: "Redshift cluster \($rs.ClusterIdentifier) accepts unencrypted connections (require_ssl is off in its parameter group)",
           fix: "Set require_ssl = true in the cluster's parameter group (it applies after a reboot)."}),
      (select($x.logging == false)
       | $b + {check: "data.redshift_no_audit_log", severity: (if is_prd($cfg; $e) then "warning" else "info" end),
           message: "Redshift cluster \($rs.ClusterIdentifier) keeps no audit log of connections and queries",
           fix: "Turn on audit logging (to CloudWatch Logs or S3), and enable_user_activity_logging in the parameter group."}),
      (select(($rs.EnhancedVpcRouting // false) | not)
       | $b + {check: "data.redshift_no_vpc_routing", severity: "info",
           message: "Redshift cluster \($rs.ClusterIdentifier) sends COPY and UNLOAD traffic over the internet, not through the VPC",
           fix: "Set enhanced_vpc_routing = true (and give the VPC an S3 gateway endpoint)."}),
      (select(($rs.AutomatedSnapshotRetentionPeriod // 1) == 0)
       | $b + {check: "data.redshift_no_snapshots", severity: "error", message: "Redshift cluster \($rs.ClusterIdentifier) takes no automated snapshots",
           fix: "Set automated_snapshot_retention_period to at least 7."}),
      (select(($rs.IamRoles // []) | length == 0)
       | $b + {check: "data.redshift_no_iam_role", severity: "info",
           message: "Redshift cluster \($rs.ClusterIdentifier) has no IAM role, so COPY and UNLOAD need access keys in the SQL",
           fix: "Attach an IAM role for S3 access and use IAM_ROLE in COPY and UNLOAD."})
    )),

  # --- ElastiCache ----------------------------------------------------------------------------
  ( $in.cache.ReplicationGroups // [] | .[] | . as $rg
    | ($rg.ReplicationGroupId | env_from_name // $cfg.account_env[$cfg.label]) as $e
    | base("elasticache/\($rg.ReplicationGroupId)"; {type: "elasticache", profile: $in.label, region: $in.region, id: $rg.ReplicationGroupId}) as $b
    | select(listed($cfg; $rg.ReplicationGroupId) | not)
    | (
      (select(($rg.TransitEncryptionEnabled // false) | not)
       | $b + {check: "data.cache_no_tls", severity: (if is_prd($cfg; $e) then "error" else "warning" end),
           message: "ElastiCache \($rg.ReplicationGroupId) accepts unencrypted connections",
           fix: "Turn on transit encryption (preferred mode first, then required, so clients can switch to TLS without an outage)."}),
      (select(($rg.AtRestEncryptionEnabled // false) | not)
       | $b + {check: "data.cache_unencrypted", severity: "warning", message: "ElastiCache \($rg.ReplicationGroupId) stores its data and backups unencrypted",
           fix: "At-rest encryption can only be set at creation: create an encrypted group from a backup and switch over."}),
      (select(($rg.AuthTokenEnabled // false | not) and (($rg.UserGroupIds // []) | length == 0))
       | $b + {check: "data.cache_no_auth", severity: "warning", message: "ElastiCache \($rg.ReplicationGroupId) needs no password: anything that can reach it can read and write",
           fix: "Use RBAC (a user group with users) or an AUTH token from Secrets Manager; both need transit encryption."}),
      (select(is_prd($cfg; $e) and ($rg.AutomaticFailover // "disabled") != "enabled")
       | $b + {check: "data.cache_no_failover", severity: "warning", message: "Production ElastiCache \($rg.ReplicationGroupId) has no automatic failover, so a node failure is an outage",
           fix: "Add a replica in another zone and set automatic_failover_enabled and multi_az_enabled."}),
      (select(is_prd($cfg; $e) and ($rg.SnapshotRetentionLimit // 0) == 0)
       | $b + {check: "data.cache_no_backups", severity: "info", message: "Production ElastiCache \($rg.ReplicationGroupId) keeps no backups",
           fix: "Set snapshot_retention_limit (for example 7)."})
    )),

  # --- Secrets Manager ------------------------------------------------------------------------
  ( $in.secrets.SecretList // [] | .[] | select(.DeletedDate == null) | . as $s
    | base("secret/\($s.Name)"; {type: "secret", profile: $in.label, region: $in.region, id: $s.ARN}) as $b
    | select(listed($cfg; $s.Name) | not)
    | (
      (select(($s.RotationEnabled // false) and ($s.RotationRules.AutomaticallyAfterDays // null) != null and
              (days_ago($in.now; $s.LastRotatedDate // $s.CreatedDate) // 0) > (($s.RotationRules.AutomaticallyAfterDays) * 2))
       | $b + {check: "data.secret_rotation_failing", severity: "error",
           message: "Secret \($s.Name) should rotate every \($s.RotationRules.AutomaticallyAfterDays) days but last rotated \(days_ago($in.now; $s.LastRotatedDate // $s.CreatedDate)) days ago",
           fix: "Rotation is failing. Diagnose shows its status; the rotation Lambda's CloudWatch logs say why (usually network access to the database, or its permissions)."}),
      (select(($s.LastAccessedDate // null) != null and days_ago($in.now; $s.LastAccessedDate) > $cfg.unused_days)
       | $b + {check: "data.secret_unused", severity: "info",
           message: "Secret \($s.Name) hasn't been read in \(days_ago($in.now; $s.LastAccessedDate)) days",
           fix: "Delete it if nothing needs it (it costs $\($cfg.secret_month | usd) a month).", savings_usd_month: $cfg.secret_month})
    ))
)
