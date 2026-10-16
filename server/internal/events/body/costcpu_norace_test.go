//go:build !race

package body

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCostCPUContinuousPartition(t *testing.T) {
	old := []int64{0, 0, 7, 7}
	if old[1]-old[0]+old[3]-old[2] != 0 {
		t.Fatal("invalid regression fixture")
	}
	got, err := costCPUTotals([]costCPUSample{{0, 0}, {0, 0}, {7, 0}}, 1, 1)
	if err != nil || got.total != 7 || got.preflight != 0 || got.decode != 7 {
		t.Fatalf("%+v %v", got, err)
	}
}
func TestCostCPUArithmetic(t *testing.T) {
	for _, c := range []struct {
		sec, usec, want int64
		bad             bool
	}{
		{1, 2, 1000002000, false}, {0, 999999, 999999000, false}, {-1, 0, 0, true}, {0, -1, 0, true}, {0, 1000000, 0, true},
		{math.MaxInt64, 0, 0, true}, {math.MaxInt64 / 1000000000, 999999, 0, true},
	} {
		got, err := costCPUTimeval(c.sec, c.usec)
		if (err != nil) != c.bad || !c.bad && got != c.want {
			t.Fatalf("%+v: %d %v", c, got, err)
		}
	}
	if _, err := costCPUSum(costCPUSample{math.MaxInt64, 1}); err == nil {
		t.Fatal("sum overflow accepted")
	}
	var overflowSamples [65]costCPUSample
	for i := range overflowSamples {
		overflowSamples[i].user = int64(i)
	}
	if _, err := costCPUTotals(overflowSamples[:], math.MaxInt, 32); err == nil {
		t.Fatal("q overflow accepted")
	}
	for _, samples := range [][]costCPUSample{
		{{0, 0}, {0, 0}, {0, 0}}, {{0, 0}, {2, 0}, {1, 1}}, {{1, 1}, {0, 2}, {2, 2}}, {{0, 0}, {1, 0}},
	} {
		if _, err := costCPUTotals(samples, 1, 1); err == nil {
			t.Fatalf("accepted %+v", samples)
		}
	}
	if _, err := costCPUTotals([]costCPUSample{{0, 0}, {1, 0}, {2, 0}}, 0, 1); err == nil {
		t.Fatal("zero N accepted")
	}
	if _, err := costCPUTotals([]costCPUSample{{0, 0}, {1, 0}, {2, 0}}, 1, 2); err == nil {
		t.Fatal("wrong repeats accepted")
	}
	total, err := costCPUTotals([]costCPUSample{{0, 0}, {1, 0}, {2, 0}}, 2, 1)
	if err != nil || total.total/total.q != 1 || total.preflight/total.q != 0 || total.total/total.q-total.preflight/total.q != 1 {
		t.Fatalf("division remainder lost: %+v %v", total, err)
	}
}
func TestCostCPUGuardedBound(t *testing.T) {
	if err := costCPUBound(312498000, 131072, 32); err != nil {
		t.Fatal(err)
	}
	if err := costCPUBound(312498001, 131072, 32); err == nil {
		t.Fatal("fractional overrun accepted")
	}
	if err := costCPUBound(math.MaxInt64, 131072, 32); err == nil {
		t.Fatal("guard overflow accepted")
	}
	if err := costCPUBound(1, math.MaxUint64, math.MaxInt64); err != nil {
		t.Fatal("arbitrary-precision product was wrapped", err)
	}
	if err := costCPUBound(0, 131072, 1); err == nil {
		t.Fatal("zero CPU accepted")
	}
}

type costCPUSample struct{ user, system int64 }
type costCPUValues struct{ preflight, decode, total, q int64 }
type costCPUStorage struct {
	samples                [65]costCPUSample
	clock                  costCPUClock
	count                  int
	readErr, valuesErr     error
	preflight, decode, cpu time.Duration
}

//go:noinline
func newCostCPUStorage() *costCPUStorage { return new(costCPUStorage) }

// normalize keeps derived temporaries in the post-baseline CPU storage.
func (storage *costCPUStorage) normalize(n, repeats int) {
	values, err := costCPUTotals(storage.samples[:storage.count], n, repeats)
	storage.valuesErr = err
	if err == nil {
		storage.cpu = time.Duration(values.total / values.q)
		storage.preflight = time.Duration(values.preflight / values.q)
		storage.decode = storage.cpu - storage.preflight
	}
}

// CPU formatting has a separate frame and is called only after sampler shutdown.
func emitCostCPULedger(t *testing.T, storage *costCPUStorage, key, mode string, n, repeats int) {
	t.Helper()
	for index, boundary := range storage.samples[:storage.count] {
		fmt.Printf("COST_CPU_SAMPLE case=%s mode=%s index=%d user_ns=%d system_ns=%d\n", key, mode, index, boundary.user, boundary.system)
	}
	if storage.readErr != nil {
		t.Fatalf("CPU read failed: %v raw_clock=%+v", storage.readErr, storage.clock)
	}
	if storage.valuesErr != nil {
		t.Fatal(storage.valuesErr)
	}
	values, err := costCPUTotals(storage.samples[:storage.count], n, repeats)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("COST_CPU case=%s mode=%s source=linux-getrusage samples=%d preflight_total_ns=%d decode_total_ns=%d total_ns=%d guard_ns=2000\n", key, mode, storage.count, values.preflight, values.decode, values.total)
}

func costCPUTimeval(sec, usec int64) (int64, error) {
	if sec < 0 || usec < 0 || usec > 999999 || sec > math.MaxInt64/1000000000 {
		return 0, errorString("invalid CPU timeval")
	}
	ns := sec * 1000000000
	if usec > (math.MaxInt64-ns)/1000 {
		return 0, errorString("CPU timeval overflow")
	}
	return ns + usec*1000, nil
}
func costCPUSum(s costCPUSample) (int64, error) {
	if s.user < 0 || s.system < 0 || s.user > math.MaxInt64-s.system {
		return 0, errorString("CPU counter overflow")
	}
	return s.user + s.system, nil
}
func costCPUTotals(samples []costCPUSample, n, repeats int) (costCPUValues, error) {
	var v costCPUValues
	if n <= 0 || (repeats != 1 && repeats != 32) || len(samples) != 2*repeats+1 || int64(n) > math.MaxInt64/int64(repeats) {
		return v, errorString("invalid CPU samples or divisor")
	}
	v.q = int64(n) * int64(repeats)
	first, err := costCPUSum(samples[0])
	if err != nil {
		return v, err
	}
	previous := first
	for i := 1; i < len(samples); i++ {
		current, err := costCPUSum(samples[i])
		if err != nil {
			return v, err
		}
		if samples[i].user < samples[i-1].user || samples[i].system < samples[i-1].system {
			return v, errorString("backward CPU counter")
		}
		delta := current - previous
		if i%2 == 1 {
			v.preflight += delta
		} else {
			v.decode += delta
		}
		previous = current
	}
	v.total = previous - first
	if v.total <= 0 || v.preflight > math.MaxInt64-v.decode || v.preflight+v.decode != v.total {
		return v, errorString("invalid CPU total")
	}
	return v, nil
}
func costCPUBound(total int64, paid uint64, q int64) error {
	if total <= 0 || total > math.MaxInt64-2000 || paid == 0 || q <= 0 {
		return errorString("invalid guarded CPU cost")
	}
	var left, right, factor big.Int
	left.SetInt64(total + 2000)
	factor.SetInt64(64 << 20)
	left.Mul(&left, &factor)
	right.SetUint64(paid)
	factor.SetInt64(5000000000)
	right.Mul(&right, &factor)
	factor.SetInt64(q)
	right.Mul(&right, &factor)
	if left.Cmp(&right) > 0 {
		return errorString("CPU exceeds paid-charge bound")
	}
	return nil
}
func costCPUInteger(value string) (int64, error) {
	if value == "" {
		return 0, errorString("empty CPU integer")
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, errorString("malformed CPU integer")
		}
	}
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errorString("CPU integer overflow")
	}
	return v, nil
}
func costCPUFields(text string, keys string, key, mode string) (map[string]string, error) {
	f := map[string]string{}
	for _, field := range strings.Fields(text) {
		k, v, ok := strings.Cut(field, "=")
		if !ok || k == "" || v == "" {
			return nil, errorString("malformed CPU field")
		}
		if _, ok := f[k]; ok {
			return nil, errorString("duplicate CPU field")
		}
		f[k] = v
	}
	if len(f) != len(strings.Fields(keys)) {
		return nil, errorString("unexpected CPU fields")
	}
	for _, k := range strings.Fields(keys) {
		if f[k] == "" {
			return nil, errorString("missing CPU field")
		}
	}
	if f["case"] != key || f["mode"] != mode {
		return nil, errorString("CPU ledger for another case or mode")
	}
	return f, nil
}
func validateCostCPU(output []byte, f map[string]string, n int, paid uint64) ([]string, error) {
	key, mode := f["case"], f["mode"]
	var samples []costCPUSample
	var summary map[string]string
	var lines []string
	for _, line := range strings.Split(string(output), "\n") {
		if i := strings.Index(line, "COST_CPU_SAMPLE "); i >= 0 {
			if summary != nil || len(samples) >= 65 {
				return nil, errorString("out-of-order CPU samples")
			}
			fields, err := costCPUFields(line[i+16:], "case mode index user_ns system_ns", key, mode)
			if err != nil {
				return nil, err
			}
			index, err := costCPUInteger(fields["index"])
			if err != nil || index != int64(len(samples)) {
				return nil, errorString("noncontiguous CPU samples")
			}
			u, err := costCPUInteger(fields["user_ns"])
			if err != nil {
				return nil, err
			}
			s, err := costCPUInteger(fields["system_ns"])
			if err != nil {
				return nil, err
			}
			samples = append(samples, costCPUSample{u, s})
			lines = append(lines, strings.TrimSpace(line[i:]))
		} else if i := strings.Index(line, "COST_CPU "); i >= 0 {
			if summary != nil {
				return nil, errorString("duplicate CPU summary")
			}
			var err error
			summary, err = costCPUFields(line[i+9:], "case mode source samples preflight_total_ns decode_total_ns total_ns guard_ns", key, mode)
			if err != nil {
				return nil, err
			}
			lines = append(lines, strings.TrimSpace(line[i:]))
		}
	}
	if summary == nil || summary["source"] != "linux-getrusage" || summary["guard_ns"] != "2000" {
		return nil, errorString("missing or unsupported CPU ledger")
	}
	repeats := 1
	size, err := costCPUInteger(f["size"])
	if err != nil {
		return nil, err
	}
	codecs, err := costCPUInteger(f["codecs"])
	if err != nil {
		return nil, err
	}
	if size <= 128<<10 || codecs == 0 {
		repeats = 32
	}
	if f["repeats"] != strconv.Itoa(repeats) {
		return nil, errorString("wrong CPU repetitions")
	}
	v, err := costCPUTotals(samples, n, repeats)
	if err != nil {
		return nil, err
	}
	for k, want := range map[string]int64{"samples": int64(len(samples)), "preflight_total_ns": v.preflight, "decode_total_ns": v.decode, "total_ns": v.total} {
		got, err := costCPUInteger(summary[k])
		if err != nil || got != want {
			return nil, errorString("CPU summary disagrees with samples")
		}
	}
	cpu, p := v.total/v.q, v.preflight/v.q
	for k, want := range map[string]int64{"preflight_cpu_ns": p, "decode_cpu_ns": cpu - p, "cpu_ns": cpu, "cpu_ms": cpu / 1000000} {
		got, err := costCPUInteger(f[k])
		if err != nil || got != want {
			return nil, errorString("CPU measurement disagrees with ledger")
		}
	}
	if err := costCPUBound(v.total, paid, v.q); err != nil {
		return nil, err
	}
	return lines, nil
}

func costCPUTestLedger(key, mode string, total, preflight int64, repeats int) string {
	var out strings.Builder
	for index := 0; index < 2*repeats+1; index++ {
		value := int64(0)
		if index == 1 {
			value = preflight
		}
		if index >= 2 {
			value = total
		}
		fmt.Fprintf(&out, "COST_CPU_SAMPLE case=%s mode=%s index=%d user_ns=%d system_ns=0\n", key, mode, index, value)
	}
	fmt.Fprintf(&out, "COST_CPU case=%s mode=%s source=linux-getrusage samples=%d preflight_total_ns=%d decode_total_ns=%d total_ns=%d guard_ns=2000\n", key, mode, 2*repeats+1, preflight, total-preflight, total)
	return out.String()
}
func TestCostCPULedger(t *testing.T) {
	for _, mode := range []string{"limited", "reference"} {
		for _, repeats := range []int{1, 32} {
			size := "131073"
			if repeats == 32 {
				size = "103"
			}
			q := int64(2 * repeats)
			total, preflight := int64(133), int64(3)
			fields := map[string]string{"case": "fixture", "mode": mode, "size": size, "codecs": "1", "repeats": strconv.Itoa(repeats), "preflight_cpu_ns": strconv.FormatInt(preflight/q, 10), "decode_cpu_ns": strconv.FormatInt(total/q-preflight/q, 10), "cpu_ns": strconv.FormatInt(total/q, 10), "cpu_ms": "0"}
			ledger := costCPUTestLedger("fixture", mode, total, preflight, repeats)
			if _, err := validateCostCPU([]byte(ledger), fields, 2, 131073); err != nil {
				t.Fatal(err)
			}
			for name, bad := range map[string]string{
				"old-record": "", "missing": strings.Replace(ledger, "index=1 ", "index=2 ", 1),
				"duplicate": strings.Replace(ledger, "index=2 ", "index=1 ", 1),
				"order":     strings.Replace(ledger, "index=0 ", "index=1 ", 1),
				"source":    strings.Replace(ledger, "linux-getrusage", "runtime", 1), "guard": strings.Replace(ledger, "guard_ns=2000", "guard_ns=0", 1),
				"other-case": strings.Replace(ledger, "case=fixture", "case=other", 1), "other-mode": strings.Replace(ledger, "mode="+mode, "mode=other", 1),
				"malformed": strings.Replace(ledger, "user_ns=0", "user_ns=-1", 1), "overflow": strings.Replace(ledger, "user_ns=0", "user_ns=9223372036854775808", 1),
				"raw-total": strings.Replace(ledger, "total_ns=133", "total_ns=132", 1), "unknown": strings.Replace(ledger, "source=linux-getrusage", "source=linux-getrusage extra=0", 1),
				"duplicate-field": strings.Replace(ledger, "guard_ns=2000", "guard_ns=2000 guard_ns=2000", 1),
			} {
				if _, err := validateCostCPU([]byte(bad), fields, 2, 131073); err == nil {
					t.Fatalf("%s %d %s accepted", mode, repeats, name)
				}
			}
			fields["cpu_ns"] = "99"
			if _, err := validateCostCPU([]byte(ledger), fields, 2, 131073); err == nil {
				t.Fatal("summary disagreement accepted")
			}
		}
	}
}

func TestCostCPUZeroDisplayedAverage(t *testing.T) {
	fields := map[string]string{"case": "small", "mode": "limited", "n": "1", "window": "103", "size": "103", "weight": "5000000", "paid": "131072", "baseline": "1000000", "limit": "6000000", "peak": "1000000", "peak_ratio": "0.167", "codecs": "0", "repeats": "32", "cpu_ns": "0", "preflight_cpu_ns": "0", "decode_cpu_ns": "0", "cpu_ms": "0"}
	output := []byte(costCPUTestLedger("small", "limited", 1, 0, 32))
	if err := validateCostChildValues(output, fields, 1, 103, 103, 5000000, 131072); err != nil {
		t.Fatal(err)
	}
	output = []byte(costCPUTestLedger("small", "limited", 0, 0, 32))
	if err := validateCostChildValues(output, fields, 1, 103, 103, 5000000, 131072); err == nil || !strings.Contains(err.Error(), string(output)) {
		t.Fatal("zero interval accepted or diagnostics lost")
	}
}
