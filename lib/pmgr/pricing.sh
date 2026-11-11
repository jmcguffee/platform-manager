# shellcheck shell=bash
# shellcheck disable=SC2054  # commas inside Type=...,Field=...,Value=... are the AWS CLI's filter syntax
# On-demand list prices from the AWS Pricing API, cached for two weeks.
#
# Savings are estimates at on-demand list prices. Reserved Instances, Savings Plans and spot
# make real costs lower, so the UI labels them "at list price".

price_cache() { printf '%s' "${XDG_CACHE_HOME:-$HOME/.cache}/platform-manager/prices.json"; }

# rds_engine ENGINE : the Pricing API's databaseEngine name.
rds_engine() {
  case $1 in
    aurora-postgresql) echo "Aurora PostgreSQL" ;; aurora-mysql | aurora) echo "Aurora MySQL" ;;
    postgres) echo PostgreSQL ;; mysql) echo MySQL ;; mariadb) echo MariaDB ;;
    oracle*) echo Oracle ;; sqlserver*) echo "SQL Server" ;; *) echo "$1" ;;
  esac
}

# price_hourly SERVICE REGION TYPE [ENGINE] [DEPLOYMENT] : USD per hour, or nothing if unknown.
# SERVICE: rds | elasticache | redshift | msk | ec2. Uses the first working AWS profile ($PRICE_PROFILE).
price_hourly() {
  local svc=$1 region=$2 type=$3 engine=${4:-} deploy=${5:-} key cache code filters=()
  key="$svc|$region|$type|$engine|$deploy"
  cache=$(price_cache)
  if [ -f "$cache" ]; then
    local hit
    hit=$(jq -r --arg k "$key" --argjson now "$(date +%s)" \
      '.[$k] | select(. != null and ($now - .at) < 1209600) | .usd // empty' "$cache" 2>/dev/null)
    [ -n "$hit" ] && { [ "$hit" != none ] && printf '%s' "$hit"; return 0; }
  fi
  [ -n "${PRICE_PROFILE:-}" ] || return 0

  filters=(Type=TERM_MATCH,Field=instanceType,Value="$type" Type=TERM_MATCH,Field=regionCode,Value="$region")
  local cache_engine=Redis
  [ "$engine" = memcached ] && cache_engine=Memcached
  [ "$engine" = valkey ] && cache_engine=Valkey
  case $svc in
    rds) code=AmazonRDS
      filters+=(Type=TERM_MATCH,Field=databaseEngine,Value="$(rds_engine "$engine")"
        Type=TERM_MATCH,Field=deploymentOption,Value="${deploy:-Single-AZ}") ;;
    elasticache) code=AmazonElastiCache
      filters+=(Type=TERM_MATCH,Field=cacheEngine,Value="$cache_engine") ;;
    redshift) code=AmazonRedshift ;;
    msk) code=AmazonMSK  # MSK prices brokers by computeFamily, without the "kafka." prefix
      filters=(Type=TERM_MATCH,Field=computeFamily,Value="${type#kafka.}" Type=TERM_MATCH,Field=regionCode,Value="$region"
        Type=TERM_MATCH,Field=group,Value=Broker) ;;
    ec2) code=AmazonEC2
      filters+=(Type=TERM_MATCH,Field=operatingSystem,Value=Linux Type=TERM_MATCH,Field=tenancy,Value=Shared
        Type=TERM_MATCH,Field=preInstalledSw,Value=NA Type=TERM_MATCH,Field=capacitystatus,Value=Used) ;;
    *) return 0 ;;
  esac
  local usd=""
  if capture "price" aws pricing get-products --service-code "$code" --region us-east-1 --profile "$PRICE_PROFILE" \
    --filters "${filters[@]}" --max-results 20 --output json --cli-connect-timeout 5 --cli-read-timeout 20; then
    # PriceList entries are JSON strings. Take the hourly on-demand price that isn't zero.
    usd=$(out price | jq -r '[.PriceList[] | fromjson | .terms.OnDemand // {} | .[] | .priceDimensions[]
        | select((.unit | test("^(Hrs|Hours|hour)"; "i")) and .pricePerUnit.USD != null) | .pricePerUnit.USD | tonumber
        | select(. > 0)] | min // empty' 2>/dev/null)
  else
    return 0  # don't cache a failed call
  fi
  mkdir -p "$(dirname "$cache")"
  [ -f "$cache" ] || printf '{}' >"$cache"
  jq --arg k "$key" --arg usd "${usd:-none}" --argjson now "$(date +%s)" '. + {($k): {usd: $usd, at: $now}}' "$cache" \
    >"$cache.tmp" && mv "$cache.tmp" "$cache"
  [ -n "$usd" ] && printf '%s' "$usd"
  return 0
}

# price_rows : stdin JSON lines with {svc, region, type, engine, deploy}; stdout {key: usd_hour}.
price_rows() {
  local svc region type engine deploy map="{}" usd
  while IFS=$'\t' read -r svc region type engine deploy; do
    [ -n "$type" ] || continue
    usd=$(price_hourly "$svc" "$region" "$type" "$engine" "$deploy")
    [ -n "$usd" ] && map=$(jq -c --arg k "$svc|$region|$type|$engine|$deploy" --argjson u "$usd" '. + {($k): $u}' <<<"$map")
  done < <(jq -r '[.svc, .region, .type, (.engine // ""), (.deploy // "")] | @tsv' | sort -u)
  printf '%s' "$map"
}
