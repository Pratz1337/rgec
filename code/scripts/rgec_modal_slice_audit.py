"""Run the independent byte audit against existing durable evidence on Modal."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import traceback


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(data)
    return value.hexdigest()


config = json.load(open('/slice-audit-config.json'))
root = '/audit-work/' + config['prefix']
target = '/retained/' + config['prefix'] + '/' + config['audit_name']
os.chmod('/retained', 0o700)
os.makedirs(root); os.mkdir(target, 0o700)
result = {'returncode': 1, 'native_compiler_actions': 0, 'input_manifest_sha256': config['manifest_sha256'],
    'auditor_sha256': digest('/audit_rgec_generated_slice.py'),
    'audit_python_version': sys.version, 'audit_python_executable_sha256': digest(sys.executable)}
try:
    assert result['auditor_sha256'] == config['auditor_sha256']
    assert digest('/slice-audit-inputs.tar.gz') == config['inputs_archive_sha256']
    with tarfile.open('/slice-audit-inputs.tar.gz') as stream:
        members = stream.getmembers()
        assert all(m.isfile() and m.name == 'raw/' + os.path.basename(m.name) for m in members)
        assert len({m.name for m in members}) == len(members)
        for member in members:
            with open(root + '/' + os.path.basename(member.name), 'wb') as output:
                shutil.copyfileobj(stream.extractfile(member), output)
    assert digest(root + '/evidence.json') == config['manifest_sha256']
    manifest = json.load(open(root + '/evidence.json'))
    for worker in manifest['sandboxes']:
        phase = worker['phase']; folder = root + '/' + phase
        retained = '/retained/' + config['prefix'] + '/' + phase
        os.mkdir(folder)
        archive = retained + '/raw.tar.gz'
        assert digest(archive) == worker['raw_archive_sha256']
        os.symlink(archive, folder + '/raw.tar.gz')
        for name in ('stdout', 'stderr'):
            os.symlink(retained + '/' + name, root + '/' + phase + '.' + name)
        with tarfile.open(archive) as stream:
            members = stream.getmembers()
            assert all(m.isfile() and m.name == 'raw/' + os.path.basename(m.name) for m in members)
            assert len({m.name for m in members}) == len(members)
            for member in members:
                with open(folder + '/' + os.path.basename(member.name), 'wb') as output:
                    shutil.copyfileobj(stream.extractfile(member), output)
    with open(target + '/stdout', 'wb') as stdout, open(target + '/stderr', 'wb') as stderr:
        result['returncode'] = subprocess.call([sys.executable, '-I', '/audit_rgec_generated_slice.py', root],
            cwd='/', stdout=stdout, stderr=stderr)
    if result['returncode'] == 0:
        shutil.copyfile(root + '/independent-slice-audit.json', target + '/independent-slice-audit.json')
        result['audit_sha256'] = digest(target + '/independent-slice-audit.json')
except BaseException:
    with open(target + '/stderr', 'a') as stderr:
        traceback.print_exc(file=stderr)
finally:
    with open(target + '/result.json', 'w') as stream:
        json.dump(result, stream, indent=2)
sys.exit(result['returncode'])
