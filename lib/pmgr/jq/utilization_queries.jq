# CloudWatch GetMetricData queries for one account's resources.
#
# Input: {rds, redshift, cache, msk} from the describe calls (msk carries its broker IDs).
# Output: [{id, service, resource, metric, stat, query}] where .query is one MetricDataQuery.
# Every metric is fetched hourly; utilization.jq turns the series into averages, p95s and peaks.

def q($ns; $metric; $dims; $stat):
  {ns: $ns, metric: $metric, dims: $dims, stat: $stat};

[
  ( .rds.DBInstances // [] | .[] | . as $db
    | {DBInstanceIdentifier: .DBInstanceIdentifier} as $d
    | (if .DBInstanceClass == "db.serverless"
       then q("AWS/RDS"; "ACUUtilization"; $d; "Average"), q("AWS/RDS"; "ACUUtilization"; $d; "Maximum")
       else q("AWS/RDS"; "CPUUtilization"; $d; "Average"), q("AWS/RDS"; "CPUUtilization"; $d; "Maximum") end),
      q("AWS/RDS"; "DatabaseConnections"; $d; "Maximum"),
      q("AWS/RDS"; "FreeableMemory"; $d; "Minimum"),
      (if (.Engine | startswith("aurora")) | not then q("AWS/RDS"; "FreeStorageSpace"; $d; "Minimum") else empty end),
      (if (.DBInstanceClass | startswith("db.t")) then q("AWS/RDS"; "CPUCreditBalance"; $d; "Minimum") else empty end)
    | . + {service: "rds", resource: $db.DBInstanceIdentifier} ),

  ( .redshift.Clusters // [] | .[] | . as $c | {ClusterIdentifier: .ClusterIdentifier} as $d
    | ( q("AWS/Redshift"; "CPUUtilization"; $d; "Average"), q("AWS/Redshift"; "CPUUtilization"; $d; "Maximum"),
        q("AWS/Redshift"; "PercentageDiskSpaceUsed"; $d; "Maximum"), q("AWS/Redshift"; "DatabaseConnections"; $d; "Maximum") )
    | . + {service: "redshift", resource: $c.ClusterIdentifier} ),

  ( .cache.CacheClusters // [] | .[] | . as $c | {CacheClusterId: .CacheClusterId} as $d
    | (if .Engine == "memcached" then "CPUUtilization" else "EngineCPUUtilization" end) as $cpu
    | ( q("AWS/ElastiCache"; $cpu; $d; "Average"), q("AWS/ElastiCache"; $cpu; $d; "Maximum"),
        (if .Engine == "memcached" then empty else q("AWS/ElastiCache"; "DatabaseMemoryUsagePercentage"; $d; "Maximum") end),
        q("AWS/ElastiCache"; "Evictions"; $d; "Sum"), q("AWS/ElastiCache"; "CurrConnections"; $d; "Maximum") )
    | . + {service: "elasticache", resource: $c.CacheClusterId} ),

  ( .msk // [] | .[] | . as $k | .brokers[] as $b
    | {"Cluster Name": $k.ClusterName, "Broker ID": ($b | tostring)} as $d
    | ( q("AWS/Kafka"; "CpuUser"; $d; "Average"), q("AWS/Kafka"; "CpuSystem"; $d; "Average"),
        q("AWS/Kafka"; "KafkaDataLogsDiskUsed"; $d; "Maximum") )
    | . + {service: "msk", resource: $k.ClusterName, broker: ($b | tostring)} )
]
| to_entries
| map(.value + {id: "m\(.key)"}
      | . + {query: {Id: .id, ReturnData: true,
                     MetricStat: {Metric: {Namespace: .ns, MetricName: .metric,
                                           Dimensions: (.dims | to_entries | map({Name: .key, Value: .value}))},
                                  Period: 3600, Stat: .stat}}})
