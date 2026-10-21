"""Retain the real native report experiment independently of its SDK connection."""
import glob
import hashlib
import json
import os
import sys
import tarfile
import traceback

sys.path.insert(0, '/')


def sha(data): return hashlib.sha256(data).hexdigest()


config = json.load(open('/report-retention-config.json'))
target = '/retained/' + config['prefix']
os.chmod('/retained', 0o700)
os.mkdir(target, 0o700)
stdout = open(target + '/reports.stdout', 'wb'); stderr = open(target + '/reports.stderr', 'wb')
os.dup2(stdout.fileno(), 1); os.dup2(stderr.fileno(), 2)
result = {'tool_sha256': {}, 'returncode': 1}
try:
    for path, expected in config['tool_sha256'].items():
        actual = sha(open(path, 'rb').read())
        result['tool_sha256'][path] = actual
        assert actual == expected, path
    os.mkdir('/transfer-v23')
    with tarfile.open('/report-prior-packets.tar.gz') as stream:
        for member in stream:
            assert member.isfile() and member.name == 'raw/' + os.path.basename(member.name)
            data = stream.extractfile(member).read()
            assert sha(data) == config['packet_sha256'][os.path.basename(member.name)]
            open('/transfer-v23/' + os.path.basename(member.name), 'wb').write(data)
    import rgec_native_report_probe
    rgec_native_report_probe.main()
    result['returncode'] = 0
except BaseException:
    traceback.print_exc()
finally:
    sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target + '/raw.tar.gz', 'w:gz') as stream:
        for path in glob.glob('/workspace/backend-continuation/*'):
            if os.path.isfile(path): stream.add(path, arcname='raw/' + os.path.basename(path))
    for name in ('raw.tar.gz', 'reports.stdout', 'reports.stderr'):
        result[name + '_sha256'] = sha(open(target + '/' + name, 'rb').read())
    with open(target + '/result.json', 'w') as stream: json.dump(result, stream, indent=2)
sys.exit(result['returncode'])
