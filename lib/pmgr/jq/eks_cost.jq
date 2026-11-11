# Price an EKS cluster's nodes and the savings its findings point to.
# Input: array of rows from eks_utilization.jq. Arg: $prices {key: usd_hour} for "ec2|region|type||".
# Spot and Fargate capacity isn't priced (spot list prices change constantly), so totals cover on-demand nodes.
def money: if . == null then null else (. * 100 | round) / 100 end;
def hourly($t): if $t.spot then null else $prices["ec2|\($t.region)|\($t.type)||"] end;

. as $all
| ([$all[] | select(.kind == "eks")] | first) as $c
| (if $c == null then null else
     ([$c.node_types[] | (hourly(.)) as $h | select($h != null) | $h * 730 * .count] | add // 0) + 73   # + EKS control plane
   end) as $monthly
| ($c.node_types // [] | map(select(.spot)) | map(.count) | add // 0) as $spot_nodes
| ($all[] | select(.kind == "eks") | . + {monthly_usd: ($monthly | money), spot_nodes: $spot_nodes}),
  ($all[] | select(has("check")) |
    if .check == "eks.idle_nodes" then
      . + {savings_usd_month: ([.evidence.nodes[] as $n | $c.node_type_of[$n] | hourly(.) | select(. != null) | . * 730] | add | money),
           cost_usd_month: ($monthly | money)}
    elif .check == "eks.overprovisioned" and $monthly != null then
      # Packing requests to about 80% of capacity would free the rest.
      ([.evidence.requests_cpu_pct, .evidence.requests_mem_pct] | max) as $used
      | . + {savings_usd_month: ((($monthly - 73) * ([1 - ($used / 80), 0] | max)) | money), savings_note: "up to",
             cost_usd_month: ($monthly | money)}
    else . end)
