"""Extract actual native code/table bytes on Modal; a capsule is not a certificate."""
import hashlib
import json
import os
import struct
import subprocess
import sys
import tarfile
import traceback


def sha(data): return hashlib.sha256(data).hexdigest()


config = json.load(open('/region-capsule-config.json'))
target = '/retained/' + config['prefix']; os.mkdir(target)
folder = '/workspace/region-capsule'; os.mkdir(folder)
for name, descriptor in (('stdout', 1), ('stderr', 2)):
    stream = open(target + '/' + name, 'wb'); os.dup2(stream.fileno(), descriptor)
evidence = dict(regions=[], source_files=[], commands=[], compiler_actions=0,
    complete_closure_certified=False, substantial_novelty_established=False,
    scope='Exact original ELF bytes, source/header comparison and native disassembly. No equivalence, complete footprint or useful reusable domain follows from extraction.')
result = {'returncode': 1}


def save(name, data):
    with open(folder + '/' + name, 'wb') as output: output.write(data)
    return sha(data)


def execute(label, argv):
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(timeout=120)
    row = dict(label=label, argv=argv, returncode=p.returncode,
        stdout_sha256=save(label + '.stdout', out), stderr_sha256=save(label + '.stderr', err))
    evidence['commands'].append(row)
    assert p.returncode == 0, err
    return out


try:
    native = '/usr/local/bin/clang'; body = open(native, 'rb').read()
    evidence['native_sha256'] = sha(body); assert evidence['native_sha256'] == config['native_sha256']
    assert body[:7] == b'\x7fELF\x02\x01\x01'
    header = struct.unpack_from('<HHIQQQIHHHHHH', body, 16)
    assert header[0:2] == (2, 62) and header[8] == 56
    segments = []
    for index in range(header[9]):
        kind, flags, offset, address, _, size, memory, alignment = struct.unpack_from('<II6Q', body, header[4] + index * 56)
        if kind == 1: segments.append(dict(flags=flags, offset=offset, address=address, size=size, memory=memory, alignment=alignment))
    evidence['load_segments'] = segments
    evidence['tools'] = {p: sha(open(p, 'rb').read()) for p in ('/usr/bin/nm', '/usr/bin/objdump', '/usr/bin/readelf')}
    symbols = execute('symbols', ['/usr/bin/nm', '-n', '-S', '--defined-only', native]).decode()
    execute('elf-headers', ['/usr/bin/readelf', '-h', '-l', native])
    wanted = {
        '_ZN4llvm16SelectionDAGISel16SelectCodeCommonEPNS_6SDNodeEPKhj': 'matcher-interpreter',
        '_ZZN12_GLOBAL__N_115X86DAGToDAGISel10SelectCodeEPN4llvm6SDNodeEE12MatcherTable': 'x86-matcher-table',
        '_ZNK4llvm16SelectionDAGISel12CheckAndMaskENS_7SDValueEPNS_14ConstantSDNodeEl': 'check-and-mask',
        '_ZN4llvm14FoldingSetBase19FindNodeOrInsertPosERKNS_16FoldingSetNodeIDERPv': 'folding-set-find'}
    found = set()
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) != 4 or fields[3] not in wanted: continue
        address, size = int(fields[0], 16), int(fields[1], 16); symbol = fields[3]; name = wanted[symbol]
        segment, = [s for s in segments if s['address'] <= address and address + size <= s['address'] + s['size']]
        assert not segment['flags'] & 2
        offset = segment['offset'] + address - segment['address']; data = body[offset:offset + size]
        assert len(data) == size
        evidence['regions'].append(dict(name=name, symbol=symbol, address=address, size=size,
            file_offset=offset, segment_flags=segment['flags'], sha256=save(name + '.bin', data)))
        found.add(symbol)
        if fields[2] in ('T', 't'):
            execute(name + '-disassembly', ['/usr/bin/objdump', '-d', '-C', '--start-address=%d' % address,
                '--stop-address=%d' % (address + size), native])
    assert found == set(wanted)
    for relative in config['source_files']:
        filename = relative.replace('/', '__'); upstream = open('/upstream/' + filename, 'rb').read()
        row = dict(relative_path=relative, upstream_sha256=save('upstream-' + filename, upstream))
        if relative.startswith('llvm/include/'):
            installed = '/usr/local/include/' + relative[len('llvm/include/'):]
            data = open(installed, 'rb').read()
            row.update(installed_path=installed, installed_sha256=save('installed-' + filename, data),
                byte_identical_to_upstream=data == upstream)
        evidence['source_files'].append(row)
    evidence['upstream_revision'] = config['upstream_revision']
    evidence['suite_complete'] = True; result['returncode'] = 0
except BaseException:
    traceback.print_exc()
finally:
    save('evidence.json', (json.dumps(evidence, indent=2) + '\n').encode())
    sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target + '/raw.tar.gz', 'w:gz') as archive:
        for name in sorted(os.listdir(folder)): archive.add(folder + '/' + name, arcname='raw/' + name)
    for name in ('raw.tar.gz', 'stdout', 'stderr'): result[name + '_sha256'] = sha(open(target + '/' + name, 'rb').read())
    with open(target + '/result.json', 'w') as output: json.dump(result, output, indent=2)
sys.exit(result['returncode'])
