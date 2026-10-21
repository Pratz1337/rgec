"""Retain a genuine V26 capture, sealed producer, or recipient phase on Modal."""
import glob
import hashlib
import json
import os
import sys
import tarfile
import traceback

sys.path.insert(0, '/')


def digest(path):
    with open(path, 'rb') as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
        return value.hexdigest()


config = json.load(open('/slice-retention-config.json'))
phase = sys.argv[1]
assert phase in ('capture', 'producer', 'replay-0', 'replay-1', 'replay-2')
os.chmod('/retained', 0o700)
target = '/retained/' + config['prefix'] + '/' + phase
os.makedirs(target, mode=0o700)
stdout = open(target + '/stdout', 'wb')
stderr = open(target + '/stderr', 'wb')
os.dup2(stdout.fileno(), 1); os.dup2(stderr.fileno(), 2)
result = {'tool_sha256': {}, 'returncode': 1}
try:
    for path, expected in config['tool_sha256'].items():
        actual = digest(path); result['tool_sha256'][path] = actual
        assert actual == expected, path
    for previous, expected in config['transfer_sha256'].items():
        archive = '/retained/' + config['prefix'] + '/' + previous + '/raw.tar.gz'
        assert digest(archive) == expected, previous
        destination = '/transfer-' + previous
        os.mkdir(destination)
        with tarfile.open(archive) as stream:
            members = stream.getmembers()
            assert all(m.isfile() and m.name == 'raw/' + os.path.basename(m.name) for m in members)
            assert len({m.name for m in members}) == len(members)
            for member in members:
                with open(destination + '/' + os.path.basename(member.name), 'wb') as output:
                    output.write(stream.extractfile(member).read())
    import rgec_generated_slice_probe
    rgec_generated_slice_probe.main('replay' if phase.startswith('replay') else phase)
    result['returncode'] = 0
except BaseException:
    traceback.print_exc()
finally:
    sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target + '/raw.tar.gz', 'w:gz') as stream:
        for path in glob.glob('/workspace/backend-continuation/*'):
            if os.path.isfile(path):
                stream.add(path, arcname='raw/' + os.path.basename(path))
    for name in ('raw.tar.gz', 'stdout', 'stderr'):
        result[name + '_sha256'] = digest(target + '/' + name)
    with open(target + '/result.json', 'w') as stream:
        json.dump(result, stream, indent=2)
sys.exit(result['returncode'])
