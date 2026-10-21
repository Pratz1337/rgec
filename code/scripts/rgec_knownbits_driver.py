#!/usr/bin/python3
"""Real compiler driver accounting for the private KnownBits experiment."""
import hashlib
import json
import os
import resource
import shlex
import subprocess
import sys
import time

arguments = sys.argv[1:]
output = arguments[arguments.index('-o') + 1] if '-o' in arguments else 'no-output'
label = output.replace('/', '__')
folder = os.environ['RGEC_KNOWNBITS_ACTIONS']
mode = os.environ['RGEC_KNOWNBITS_MODE']
env = dict(os.environ)
env['RGEC_KNOWNBITS_METRICS'] = folder + '/' + label + '.metrics'
if mode == 'shadow': env['RGEC_KNOWNBITS_EXPORT'] = folder + '/' + label + '.packet'
if os.environ.get('RGEC_KNOWNBITS_PEER') and os.path.isfile(os.environ['RGEC_KNOWNBITS_PEER'] + '/' + label + '.packet'):
    env['RGEC_KNOWNBITS_IMPORT'] = os.environ['RGEC_KNOWNBITS_PEER'] + '/' + label + '.packet'
before = resource.getrusage(resource.RUSAGE_CHILDREN)
start = time.monotonic()
argv = ['/usr/local/bin/clang'] + arguments
plan = None
if '-c' in arguments:
    planned = subprocess.Popen(argv + ['-###'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    planned_out, planned_error = planned.communicate()
    commands = [shlex.split(line) for line in planned_error.decode().splitlines() if '"-cc1"' in line]
    for suffix, data in (('stdout', planned_out), ('stderr', planned_error)):
        with open(folder + '/' + label + '.plan.' + suffix, 'wb') as f: f.write(data)
    assert planned.returncode == 0 and len(commands) == 1
    plan = dict(argv=argv + ['-###'], returncode=planned.returncode,
        stdout_sha256=hashlib.sha256(planned_out).hexdigest(), stderr_sha256=hashlib.sha256(planned_error).hexdigest())
    binary = '/usr/local/bin/clang' if mode == 'original' else '/rgec-knownbits-scope'
    argv = [binary] + commands[0][1:]
process = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, error = process.communicate()
after = resource.getrusage(resource.RUSAGE_CHILDREN)
for suffix, data in (('stdout', out), ('stderr', error)):
    with open(folder + '/' + label + '.' + suffix, 'wb') as f: f.write(data)
row = dict(argv=argv, driver_arguments=arguments, plan=plan, output=output, label=label, returncode=process.returncode,
    child_cpu_seconds=after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
    wall_seconds=time.monotonic() - start,
    stdout_sha256=hashlib.sha256(out).hexdigest(), stderr_sha256=hashlib.sha256(error).hexdigest())
with open(folder + '/actions.jsonl', 'a') as f: f.write(json.dumps(row) + '\n')
os.write(1, out); os.write(2, error)
sys.exit(process.returncode)
