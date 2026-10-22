#!/usr/bin/env bash
# join.sh - merge normalized NDJSON sources into inventory/details/unmapped CSVs.
#
# Repo identity is fuzzy: SBOM asset names ("org/repo") and APM git URLs
# ("host/group/project") rarely match exactly, so we key repos on their last two
# path segments (rkey) and match on that. This is the documented normalization
# step; it is intentionally lenient and marked medium confidence when it is the
# only link.

# build_reports CACHE_DIR OUT_DIR ENV_FILTER CVE_IDS PKG_FILTER AFFECTED_BELOW
build_reports() {
  local cache="$1" outdir="$2" env="${3:-}" cves_in="${4:-}" pkg_in="${5:-}" below="${6:-}"
  mkdir -p "$outdir"

  # package filter -> JSON array of lowercased names (empty = all)
  local pkg_json="[]"
  if [ -n "$pkg_in" ]; then
    pkg_json="$(printf '%s' "$pkg_in" | tr ',' '\n' \
      | jq -R 'select(length>0)|ascii_downcase|gsub("^[[:space:]]+|[[:space:]]+$";"")' | jq -sc '.')"
  fi

  # Ensure every source file exists (empty is fine for --slurpfile).
  local f
  for f in sbom_repo sbom_service sbom_host vulns spans hosts catalog; do
    [ -f "${cache}/${f}.ndjson" ] || : > "${cache}/${f}.ndjson"
  done

  local cves_json="[]"
  if [ -n "$cves_in" ]; then
    cves_json="$(printf '%s' "$cves_in" | tr ',' '\n' \
      | jq -R 'select(length>0)|ascii_downcase|gsub("^[[:space:]]+|[[:space:]]+$";"")' | jq -sc '.')"
  fi

  local combined="${cache}/_combined.json"

  jq -n \
    --arg env "$env" --argjson cves "$cves_json" \
    --argjson pkgf "$pkg_json" --arg belowver "$below" \
    --slurpfile sbom_repo "${cache}/sbom_repo.ndjson" \
    --slurpfile sbom_service "${cache}/sbom_service.ndjson" \
    --slurpfile sbom_host "${cache}/sbom_host.ndjson" \
    --slurpfile vulns     "${cache}/vulns.ndjson" \
    --slurpfile spans     "${cache}/spans.ndjson" \
    --slurpfile hosts     "${cache}/hosts.ndjson" \
    --slurpfile catalog   "${cache}/catalog.ndjson" '
    # ---- helpers ------------------------------------------------------------
    def rkey($r):
      ($r // "") | ascii_downcase | sub("\\.git$";"") | sub("/$";"")
      | (split("/") | if length >= 2 then (.[-2] + "/" + .[-1]) else (.[-1] // "") end);

    # semver-ish comparison: is version $a strictly less than $b? Pre-release and
    # build suffixes are dropped; non-numeric or missing segments count as 0.
    def vlt($a; $b):
      def norm: (. // "") | ascii_downcase | split("-")[0] | split("+")[0]
                | split(".") | map((try tonumber) // 0);
      ($a | norm) as $x | ($b | norm) as $y
      | reduce range(0; ([($x|length), ($y|length)] | max)) as $i
          ({r:0, d:false};
            if .d then .
            else (($x[$i]//0)) as $xi | (($y[$i]//0)) as $yi
              | if   $xi < $yi then {r:-1, d:true}
                elif $xi > $yi then {r:1, d:true}
                else . end
            end)
      | (.r < 0);

    # ---- host -> ips map (by hostname AND alias) ----------------------------
    ( reduce $hosts[] as $h ({};
        . + { ($h.hostname): ($h.ips // []) }
        + ( reduce ($h.aliases // [])[] as $a (.; . + { ($a): ($h.ips // []) }) )
      ) ) as $HM

    # ---- service -> [hosts], from host `service:` tags (+ spans if present) -
    # This is the bridge that does NOT depend on repo identity: a service name
    # from a Service SBOM resolves to hosts tagged service:<name>.
    | ( ( [ $hosts[] | .hostname as $hn | (.services // [])[] | {svc:(.|ascii_downcase), host:$hn} ]
          + [ $spans[] | select((.service//"")!="" and (.host//"")!="")
              | {svc:(.service|ascii_downcase), host:.host} ] )
        | reduce .[] as $p ({}; .[$p.svc] = ((.[$p.svc] // []) + [$p.host]))
        | map_values(unique) ) as $svc2hosts

    # ---- catalog: service -> rkey ------------------------------------------
    | ( reduce $catalog[] as $c ({};
          if ($c.service != "" and ($c.repo // "") != "")
          then . + { ($c.service): rkey($c.repo) } else . end) ) as $svc2rk

    # ---- span triples {service, host, rkey} --------------------------------
    | ( [ $spans[]
          | { service: .service, host: .host,
              rkey: ( if (.repo // "") != "" then rkey(.repo)
                      else ($svc2rk[.service] // "") end ) } ]
        + [ $catalog[] | select((.repo//"")!="")
            | { service: .service, host: "", rkey: rkey(.repo) } ] ) as $triples

    # ---- repo-scoped package matches (sbom repo + vulns) -------------------
    | ( [ $sbom_repo[]
          | { rkey: rkey(.repo), repo: .repo, package: .package, version: .version,
              framework: .framework, prog_lang: .prog_lang,
              cve_ids: [], severity: "", fix_version: "", data_source: "sbom_repo" } ]
        + [ $vulns[]
            | select( (.asset_type // "" | ascii_downcase) == "repository"
                      or (.asset_type // "") == "" )
            | { rkey: rkey(.repo), repo: .repo, package: .package, version: .version,
                framework: "", prog_lang: .prog_lang,
                cve_ids: .cve_ids, severity: .severity, fix_version: .fix_version,
                data_source: "vulns" } ] ) as $repo_pkgs_all

    # ---- zero-day targeting: package + version filter ----------------------
    # Done on SBOM data (package + version are right there), so it does NOT depend
    # on the deprecated/forbidden Datadog vulnerability API. --package keeps only the
    # named package(s); --affected-below keeps only versions strictly below the
    # given fixed-in version. Empty filters keep everything.
    | def keep($pkg; $ver):
        ( ($pkgf | length) == 0 or ($pkgf | index($pkg | ascii_downcase)) != null )
        and ( $belowver == "" or vlt(($ver // ""); $belowver) );
      ( [ $repo_pkgs_all[] | select(keep(.package; .version)) ] ) as $repo_pkgs
    | ( [ $sbom_host[]     | select(keep(.package; .version)) ] ) as $host_pkgs
    | ( [ $sbom_service[]  | select(keep(.package; .version)) ] ) as $svc_pkgs

    # ---- resolver: rkey -> list of {service,host,ip} ------------------------
    # rkey -> [{service, host, ip}] : services linked to this repo (via spans
    # @git.repository_url, or catalog) mapped to hosts via the service->host map.
    | def assets_for($rk):
        ( [ $triples[] | select(.rkey == $rk) | .service ] | map(select(. != "")) | unique ) as $svcs
        | [ $svcs[] as $s | (($svc2hosts[$s | ascii_downcase]) // [])[] | {service:$s, host:.} ]
        | unique_by(.service + "|" + .host)
        | map({ service: .service, host: .host, ip: (($HM[.host] // []) | join(";")) });
    def hosts_for_service($svc): ($svc2hosts[$svc | ascii_downcase] // []);

    # ---- details + unmapped -------------------------------------------------
    ( [ $repo_pkgs[]
        | . as $p | assets_for($p.rkey) as $as
        # Repo matches with NO resolvable host still appear here (blank host,
        # confidence "low") - the repo-level blast radius is the real answer when
        # the repo is not tied to an APM service/host. Resolved ones get the host.
        | ( if ($as | length) == 0 then [ {service:"", host:"", ip:""} ] else $as end )[]
        | { ip: .ip, hostname: .host, repo: $p.repo, prog_lang: $p.prog_lang,
            framework: $p.framework, package: $p.package, version: $p.version,
            service: .service, env: $env,
            cve_ids: ($p.cve_ids | join(";")), severity: $p.severity,
            fix_version: $p.fix_version, data_source: $p.data_source,
            confidence: ( if (.host // "") != ""
                          then (if ($p.version // "") != "" then "high" else "medium" end)
                          else "low" end ) } ]
      + [ $host_pkgs[]
          | { ip: (($HM[.hostname] // []) | join(";")), hostname: .hostname, repo: "",
              prog_lang: .prog_lang, framework: .framework, package: .package,
              version: .version, service: "", env: $env, cve_ids: "", severity: "",
              fix_version: "", data_source: .data_source, confidence: "high" } ]
      + [ $svc_pkgs[]
          | . as $p | hosts_for_service($p.service) as $hs
          | if ($hs | length) == 0 then empty
            else $hs[]
              | { ip: (($HM[.] // []) | join(";")), hostname: ., repo: "",
                  prog_lang: $p.prog_lang, framework: $p.framework, package: $p.package,
                  version: $p.version, service: $p.service, env: $env,
                  cve_ids: "", severity: "", fix_version: "",
                  data_source: $p.data_source,
                  confidence: (if ($p.version // "") != "" then "high" else "medium" end) }
            end ]
      | unique ) as $details

    | ( ( [ $repo_pkgs[]
            | . as $p | select( (assets_for($p.rkey) | length) == 0 )
            | { repo: $p.repo, prog_lang: $p.prog_lang, framework: $p.framework,
                package: $p.package, version: $p.version,
                cve_ids: ($p.cve_ids | join(";")), severity: $p.severity,
                fix_version: $p.fix_version, reason: "no host/IP mapping (repo not linked to a service/host)" } ]
          + [ $svc_pkgs[]
              | . as $p | select( (hosts_for_service($p.service) | length) == 0 )
              | { repo: ("service:" + $p.service), prog_lang: $p.prog_lang, framework: $p.framework,
                  package: $p.package, version: $p.version,
                  cve_ids: "", severity: "", fix_version: "",
                  reason: "service has no host (no service: tag and no span host)" } ] )
        | unique ) as $unmapped

    | ( [ $details[] | { ip, hostname, repo, prog_lang } ] | unique ) as $inventory

    | { details: $details, inventory: $inventory, unmapped: $unmapped }
  ' > "$combined" || { warn "join failed"; return 1; }

  # ---- emit CSVs -----------------------------------------------------------
  {
    printf 'ip,hostname,repo,prog_lang\n'
    jq -r '.inventory[] | [.ip,.hostname,.repo,.prog_lang] | @csv' "$combined"
  } > "${outdir}/inventory.csv"

  {
    printf 'ip,hostname,repo,prog_lang,framework,package,version,service,env,cve_ids,severity,fix_version,data_source,confidence\n'
    jq -r '.details[] | [.ip,.hostname,.repo,.prog_lang,.framework,.package,.version,.service,.env,.cve_ids,.severity,.fix_version,.data_source,.confidence] | @csv' "$combined"
  } > "${outdir}/details.csv"

  {
    printf 'repo,prog_lang,framework,package,version,cve_ids,severity,fix_version,reason\n'
    jq -r '.unmapped[] | [.repo,.prog_lang,.framework,.package,.version,.cve_ids,.severity,.fix_version,.reason] | @csv' "$combined"
  } > "${outdir}/unmapped.csv"

  # counts for the final summary
  INV_COUNT="$(( $(wc -l < "${outdir}/inventory.csv") - 1 ))"
  DET_COUNT="$(( $(wc -l < "${outdir}/details.csv") - 1 ))"
  UNMAP_COUNT="$(( $(wc -l < "${outdir}/unmapped.csv") - 1 ))"
  [ "$INV_COUNT" -ge 0 ] || INV_COUNT=0
  [ "$DET_COUNT" -ge 0 ] || DET_COUNT=0
  [ "$UNMAP_COUNT" -ge 0 ] || UNMAP_COUNT=0
  export INV_COUNT DET_COUNT UNMAP_COUNT
  return 0
}
