"""Local stand-in for the footprint harness. Failure modes are selected only by tests."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time

import samplers

IDENTITY = dict(version='0.0.0-local', commit='unknown', channel='local', sourceEpoch=0)
MODES = ('healthy', 'never-ready', 'ignore-stop', 'bad-version', 'warmup-spike', 'spin',
         'one-sample', 'frozen-sample', 'frozen-timestamps', 'frozen-counter', 'old-samples', 'wrong-pid',
         'wrong-interval', 'null-process', 'counter-reset', 'catch-up', 'debug-disabled',
         'repeated-lines', 'warmup-rotations')


def main():
    mode = os.environ.get('RICEVANTA_FAKE_MODE', 'healthy')
    if mode not in MODES:
        return 2
    identity = json.loads(os.environ.get('RICEVANTA_FAKE_IDENTITY', json.dumps(IDENTITY)))
    if sys.argv[1:] == ['version', '--json']:
        print('invalid' if mode == 'bad-version' else json.dumps(identity))
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['run'])
    for key in ('config', 'state-dir', 'runtime-dir', 'log-dir', 'log'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    raw = Path(args.config).read_bytes()
    profile = json.loads(raw)
    for directory in (args.state_dir, args.runtime_dir, args.log_dir):
        Path(directory).mkdir(parents=True, exist_ok=True)
    started = time.monotonic_ns()
    pid = os.getpid()
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        if mode != 'ignore-stop':
            stopping = True

    signal.signal(signal.SIGTERM, stop)
    if sys.platform == 'win32':
        signal.signal(signal.SIGBREAK, stop)
    else:
        signal.signal(signal.SIGINT, stop)
    counters = dict(samples=0, sample_failures=0, log_errors=0, health_write_failures=0,
                    stop_requests=0, log_rotations=0)
    sampler = samplers.current().Sampler(pid)
    log_path = Path(args.log_dir) / 'agent.log'
    process = None
    last_health = None
    last_line = None
    record_dir = os.environ.get('RICEVANTA_FAKE_RECORD')
    record_path = Path(record_dir) / (hashlib.sha256(raw).hexdigest() + '.json') if record_dir else None
    record = dict(config=args.config, config_sha256=hashlib.sha256(raw).hexdigest(),
                  config_mode=Path(args.config).stat().st_mode & 0o777, state_dir=args.state_dir,
                  log=args.log, pid=pid)

    def envelope(event, level='debug', **fields):
        return dict(ts=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                    level=level, event=event, pid=pid, **fields)

    def encode(item):
        return (json.dumps(item, sort_keys=True, separators=(',', ':')) + '\n').encode()

    def emit(item, uptime):
        line = encode(item)
        rotate = log_path.exists() and log_path.stat().st_size + len(line) > profile['log']['max_file_bytes']
        if mode == 'warmup-rotations':
            rotate = uptime < 150 and counters['log_rotations'] == 0
        if rotate:
            for i in range(profile['log']['max_files'] - 1, 0, -1):
                source = log_path if i == 1 else Path(str(log_path) + f'.{i-1}')
                dest = Path(str(log_path) + f'.{i}')
                if source.exists():
                    os.replace(source, dest)
            counters['log_rotations'] += 1
            log_path.write_bytes(encode(envelope('log_rotated', 'info', rotation=counters['log_rotations'])))
        with log_path.open('ab') as stream:
            stream.write(line)

    def health(state, uptime):
        nonlocal last_health
        wall = time.time_ns() // 1000000
        last_health = dict(schema='ricevanta-agent-health-v1', pid=pid, state=state,
                           version=identity['version'], commit=identity['commit'], channel=identity['channel'],
                           mode='run', written_unix_ms=wall, uptime_ms=uptime,
                           interval_ms=profile['health']['interval_ms'], process=process,
                           counters=dict(counters), errors=[])
        if uptime >= 150:
            if mode == 'wrong-pid':
                last_health['pid'] += 1
            if mode == 'wrong-interval':
                last_health['interval_ms'] += 100
            if mode == 'null-process':
                last_health['process'] = None
        target = Path(args.runtime_dir) / 'health.json'
        tmp = target.with_suffix('.json.tmp')
        tmp.write_text(json.dumps(last_health), encoding='utf-8')
        os.replace(tmp, target)
        if record_path:
            record_path.write_text(json.dumps(dict(record, last_health=last_health)), encoding='utf-8')

    spike = bytearray(128 * 1024 * 1024) if mode == 'warmup-spike' else None
    if spike is not None:
        for i in range(0, len(spike), 4096):
            spike[i] = 1
    next_tick = time.monotonic()
    reset_done = False
    try:
        while not stopping:
            uptime = (time.monotonic_ns() - started) // 1000000
            if spike is not None and uptime > 200:
                spike = None
            now = time.monotonic()
            if now >= next_tick:
                interval = profile['health']['interval_ms'] / 1000
                next_tick += interval
                if next_tick <= now:
                    next_tick = now + interval
                if mode == 'one-sample' and counters['samples']:
                    continue
                frozen = mode == 'frozen-sample' and counters['samples'] > 0
                if not frozen:
                    previous_process = process
                    s = sampler.sample()
                    stamp = time.time_ns() // 1000000
                    process = dict(footprint_bytes=s.footprint_bytes, footprint_metric=s.footprint_metric,
                                   threads=s.threads, cpu_user_ms=s.cpu_ns // 1000000, cpu_system_ms=0,
                                   sampled_unix_ms=stamp, sampled_uptime_ms=uptime,
                                   **{('handle_count' if s.descriptor_kind == 'handle' else 'fd_count'): s.descriptors})
                    if mode == 'frozen-timestamps' and previous_process:
                        for key in ('sampled_unix_ms', 'sampled_uptime_ms'):
                            process[key] = previous_process[key]
                    if mode == 'old-samples':
                        process['sampled_unix_ms'] -= 3600000
                    if mode != 'frozen-counter' or not counters['samples']:
                        counters['samples'] += 10 if mode == 'catch-up' else 1
                    if mode == 'counter-reset' and uptime > 650 and not reset_done:
                        counters['samples'] = 0
                        reset_done = True
                    if profile['log']['level'] == 'debug' and mode != 'debug-disabled':
                        item = envelope('sample_completed', sample=counters['samples'],
                                        sampled_uptime_ms=uptime, footprint_bytes=s.footprint_bytes,
                                        footprint_metric=s.footprint_metric, threads=s.threads,
                                        descriptor_count=s.descriptors, descriptor_kind=s.descriptor_kind,
                                        cpu_user_ms=s.cpu_ns // 1000000, cpu_system_ms=0)
                        if mode == 'repeated-lines' and last_line:
                            item = last_line
                        else:
                            last_line = item
                        emit(item, uptime)
                health('starting' if mode == 'never-ready' else 'ready', uptime)
            if mode != 'spin':
                time.sleep(0.002)
        counters['stop_requests'] += 1
        health('stopped', (time.monotonic_ns() - started) // 1000000)
    finally:
        sampler.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
