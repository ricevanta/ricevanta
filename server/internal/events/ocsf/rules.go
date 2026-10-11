package ocsf

import (
	"encoding/json"
	"strconv"

	"github.com/ricevanta/ricevanta/server/internal/events/eventid"
)

// These helpers run only after the entire event passes its closed schema.
func object(v any) map[string]any             { return v.(map[string]any) }
func array(v any) []any                       { return v.([]any) }
func text(v any) string                       { return v.(string) }
func integer(v any) uint64                    { n, _ := strconv.ParseUint(string(v.(json.Number)), 10, 64); return n }
func present(m map[string]any, k string) bool { _, ok := m[k]; return ok }
func unique(items []any, key string) bool {
	seen := map[string]bool{}
	for _, v := range items {
		k := text(object(v)[key])
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}
func semantic(rule string, e map[string]any, source Source) bool {
	switch rule {
	case "type_uid":
		if integer(e["type_uid"]) != integer(e["class_uid"])*100+integer(e["activity_id"]) {
			return false
		}
		m := object(e["metadata"])
		ids := []string{text(m["uid"]), text(m["correlation_uid"])}
		for _, k := range []string{"quarantine_uid", "event_uid", "request_uid"} {
			if v, ok := e[k]; ok {
				ids = append(ids, text(v))
			}
		}
		for _, id := range ids {
			if _, err := eventid.Parse(id); err != nil {
				return false
			}
		}
		return true
	case "bundle_state":
		m := object(e["metadata"])
		installed := m["bundle_state"] == "installed"
		if source == Agent && installed != present(m, "policy_bundle") {
			return false
		}
		if origin, ok := m["extension_origin"]; ok && source == Agent {
			return installed && integer(object(origin)["recovery_epoch"]) == integer(object(m["policy_bundle"])["recovery_epoch"])
		}
		return true
	case "coverage":
		return checkCoverage(e)
	case "sequence_range":
		v, ok := e["sequence_range"]
		if !ok {
			return true
		}
		r := object(v)
		first, last := integer(r["first"]), integer(r["last"])
		return first <= last && last-first < ^uint64(0) && integer(e["count"]) == last-first+1
	case "health_identity":
		osid := integer(object(object(e["device"])["os"])["type_id"])
		metric, forbidden := "pss", "handle_count"
		if osid == 100 {
			metric, forbidden = "private_working_set", "fd_count"
		} else if osid == 300 {
			metric = "phys_footprint"
		}
		if !unique(array(e["processes"]), "uid") || !unique(array(e["budgets"]), "unit") || !unique(array(e["spools"]), "spool_class") {
			return false
		}
		for _, v := range array(e["processes"]) {
			p := object(v)
			if p["footprint_metric"] != metric || present(p, forbidden) || !unique(array(p["event_rates"]), "source") {
				return false
			}
		}
		return true
	case "pipeline_activity":
		switch integer(e["activity_id"]) {
		case 3:
			return integer(e["count"]) == 1
		case 4:
			reason := text(e["reason"])
			switch text(e["destination_state"]) {
			case "healthy":
				return reason == "recovered"
			case "degraded":
				return reason == "retrying" || reason == "dead_letter"
			case "failed":
				return reason == "paused" || reason == "retrying"
			case "lagging":
				return reason == "lag"
			}
		}
		return true
	case "policy_activity":
		if integer(e["activity_id"]) != 7 {
			return true
		}
		m := object(e["metadata"])
		return source == Agent && m["bundle_state"] == "installed" && e["candidate_bundle_uid"] == object(m["policy_bundle"])["bundle_uid"]
	case "certificate_activity":
		c := object(e["certificate"])
		return integer(c["created_time"]) < integer(c["expiration_time"]) && (integer(e["activity_id"]) != 2 || e["prior_certificate_uid"] != c["uid"])
	case "unmapped":
		u, ok := e["unmapped"]
		if !ok {
			return true
		}
		seen := map[struct {
			field string
			index uint64
		}]bool{}
		for _, v := range array(object(u)["entries"]) {
			p := object(v)
			key := struct {
				field string
				index uint64
			}{text(p["field"]), integer(p["index"])}
			if seen[key] {
				return false
			}
			seen[key] = true
		}
		// The admitted object contains fixed ASCII keys and diagnostic tokens only.
		data, err := json.Marshal(u)
		return err == nil && len(data) <= 32768
	case "truncation":
		m := object(e["metadata"])
		count := 0
		for _, k := range []string{"is_truncated", "untruncated_size", "truncation"} {
			if present(m, k) {
				count++
			}
		}
		if count == 0 {
			return true
		}
		if count != 3 {
			return false
		}
		t := object(m["truncation"])
		original, unmapped := integer(t["original_event_bytes"]), integer(t["original_unmapped_bytes"])
		rounded := original / 1000
		if original%1000 != 0 {
			rounded++
		}
		return unmapped > 32768 && original >= unmapped && integer(m["untruncated_size"]) == rounded
	}
	return false
}
func checkCoverage(e map[string]any) bool {
	sampler := []string{"sensor_unavailable", "permission_denied", "collection_failed"}
	expected := map[string][]string{}
	absent := func(parent map[string]any, field, path string, reasons []string) {
		if !present(parent, field) {
			expected[path] = reasons
		}
	}
	osid := integer(object(object(e["device"])["os"])["type_id"])
	descriptor := "fd_count"
	if osid == 100 {
		descriptor = "handle_count"
	}
	for i, v := range array(e["processes"]) {
		p := object(v)
		for _, k := range []string{"cpu_pct", "footprint_bytes", descriptor} {
			absent(p, k, "/processes/"+strconv.Itoa(i)+"/"+k, sampler)
		}
	}
	for i, v := range array(e["budgets"]) {
		b := object(v)
		for _, k := range []string{"memory_bytes", "cpu_pct"} {
			absent(b, k, "/budgets/"+strconv.Itoa(i)+"/"+k, sampler)
		}
	}
	for i, v := range array(e["spools"]) {
		s := object(v)
		empty := integer(s["bytes"]) == 0
		if empty && present(s, "oldest_unsent_ms") {
			return false
		}
		reasons := sampler
		if empty {
			reasons = []string{"not_applicable"}
		}
		absent(s, "oldest_unsent_ms", "/spools/"+strconv.Itoa(i)+"/oldest_unsent_ms", reasons)
		absent(s, "last_ack_sequence", "/spools/"+strconv.Itoa(i)+"/last_ack_sequence", []string{"not_observed", "sensor_unavailable", "permission_denied", "collection_failed"})
	}
	absent(e, "kernel_bytes", "/kernel_bytes", []string{"not_applicable", "privacy_filtered", "sensor_unavailable", "permission_denied", "collection_failed"})
	m := object(e["metadata"])
	v, ok := m["coverage"]
	if !ok {
		return len(expected) == 0
	}
	entries := array(v)
	if len(entries) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range entries {
		c := object(v)
		path := text(c["path"])
		if seen[path] || !contains(expected[path], text(c["reason"])) {
			return false
		}
		seen[path] = true
	}
	return true
}
