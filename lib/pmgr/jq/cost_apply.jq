# Attach monthly cost to metric rows and monthly savings to findings.
# Input: array of mixed rows (metric rows have .kind, findings have .check). Arg: $prices {key: usd_hour}.
def key($p): "\($p.svc)|\($p.region)|\($p.type)|\($p.engine // "")|\($p.deploy // "")";
def usd($p): if $p == null then null else $prices[key($p)] end;
def money: if . == null then null else (. * 100 | round) / 100 end;

. as $all
| [$all[] | select(has("kind")) | (usd(.price)) as $h
   | . + {usd_hour: $h, monthly_usd: (if $h then ($h * 730 * (.nodes // 1) | money) else null end)}] as $m
| ($m[]),
  ($all[] | select(has("check")) | . as $f
   | ([$m[] | select(.kind == $f.svc and .name == $f.target)] | first) as $r
   | if $r == null then $f
     else
       (if ($f.check | endswith(".idle")) then $r.monthly_usd
        elif $f.down != null and $r.usd_hour != null then
          (usd($r.price + {type: $f.down})) as $d
          | if $d != null then (($r.usd_hour - $d) * 730 * ($r.nodes // 1)) else null end
        elif $f.check == "redshift.oversized" then ($r.monthly_usd // null) * 0.5
        else null end) as $save
       | $f + {cost_usd_month: $r.monthly_usd, savings_usd_month: ($save | money)}
     end)
