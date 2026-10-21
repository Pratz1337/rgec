"""Audit retained real CPU samples; never execute a compiler or trust pprof totals."""
import collections
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import sys
import tarfile


def sha(data): return hashlib.sha256(data).hexdigest()


def profile(data):
    assert struct.unpack_from('<5Q', data) == (0, 3, 0, 1000, 0)
    cursor = 40; records = []
    while True:
        count, depth = struct.unpack_from('<2Q', data, cursor); cursor += 16
        assert 1 <= depth <= 1024 and cursor + depth * 8 <= len(data)
        pcs = struct.unpack_from('<%dQ' % depth, data, cursor); cursor += depth * 8
        if count == 0:
            assert pcs == (0,); break
        assert pcs[0] != 0
        records.append((count, pcs))
    mappings = data[cursor:]
    assert b'/usr/local/bin/clang' in mappings and b'r-xp' in mappings
    return records, mappings


def main(root):
    m = json.loads((root / 'evidence.json').read_bytes())
    assert m['sandbox']['returncode'] == m['sandbox']['cleanup_returncode'] == 0
    for path, expected in m['source_sha256'].items():
        assert sha((root / Path(path).name).read_bytes()) == expected
    assert sha((root / 'segment-profile-config.json').read_bytes()) == m['config_sha256']
    result = json.loads((root / 'durable-result.json').read_bytes())
    assert result['returncode'] == 0 and result['raw.tar.gz_sha256'] == m['sandbox']['raw_archive_sha256']
    for name in ('raw.tar.gz', 'stdout', 'stderr'):
        assert sha((root / name).read_bytes()) == result[name + '_sha256']
    with tarfile.open(root / 'raw.tar.gz') as archive:
        members = archive.getmembers(); assert len({v.name for v in members}) == len(members)
        for member in members:
            assert member.isfile() and member.name == 'raw/' + Path(member.name).name
            assert archive.extractfile(member).read() == (root / member.name).read_bytes()
    raw = root / 'raw'; e = json.loads((raw / 'evidence.json').read_bytes())
    assert e['suite_complete'] and len(e['rows']) == 18 and len(e['plans']) == 3
    config = json.loads((root / 'segment-profile-config.json').read_bytes())
    assert e['native_sha256'] == config['native_sha256']
    for source in e['sources']:
        assert sha((raw / (Path(source['path']).name + '.original')).read_bytes()) == source['sha256']
    for row in e['plans'] + e['commands'] + e['rows']:
        assert row['returncode'] == 0
        for suffix in ('stdout', 'stderr'):
            assert sha((raw / (row['label'] + '.' + suffix)).read_bytes()) == row[suffix + '_sha256']
    indexed = {(r['source'], r['block'], r['mode']): r for r in e['rows']}
    assert len(indexed) == 18
    rng = random.Random(e['seed']); pairs = []; samples = []
    totals = collections.Counter()
    for source in e['sources']:
        name = Path(source['path']).name
        plan, = [p for p in e['plans'] if p['label'] == name + '-driver-plan']
        assert plan['argv'][-1] == '-###'
        for block in range(3):
            order = ['native', 'sampled']; rng.shuffle(order)
            native = indexed[(name, block, 'native')]; sampled = indexed[(name, block, 'sampled')]
            for mode in order:
                row = indexed[(name, block, mode)]
                assert row['order'] == order.index(mode) and row['argv'] == native['argv']
                assert row['argv'][0:2] == ['/usr/local/bin/clang', '-cc1']
                assert sha((raw / (row['label'] + '.o')).read_bytes()) == row['object_sha256']
            same = {k: native[k] == sampled[k] for k in ('returncode', 'object_sha256', 'stdout_sha256', 'stderr_sha256')}
            assert all(same[k] for k in ('returncode', 'object_sha256', 'stdout_sha256'))
            pairs.append(dict(source=name, block=block, comparisons=same))
            body = (raw / (sampled['label'] + '.profile')).read_bytes()
            assert sha(body) == sampled['profile_sha256']
            records, mappings = profile(body); count = sum(n for n, _ in records)
            annotation = (raw / (sampled['label'] + '-annotation.stdout')).read_text()
            match = re.search(r'^Total: (\d+) samples$', annotation, re.M)
            assert match and int(match.group(1)) == count
            trailer = (raw / (sampled['label'] + '.stderr')).read_bytes()
            match = re.search(rb'PROFILE: interrupts/evictions/bytes = (\d+)/\d+/\d+\n$', trailer)
            assert match and int(match.group(1)) == count
            # The captured profiler output is deliberately retained as a stream difference.
            before = trailer[:match.start()]
            assert before == (raw / (native['label'] + '.stderr')).read_bytes()
            totals[name] += count
            samples.append(dict(source=name, block=block, samples=count, records=len(records),
                mappings_sha256=sha(mappings), profiler_trailer_only_difference=True))
    audit = dict(manifest_sha256=sha((root / 'evidence.json').read_bytes()),
        auditor_sha256=sha(Path(__file__).read_bytes()), archive_sha256=sha((root / 'raw.tar.gz').read_bytes()),
        frozen_sources=len(m['source_sha256']), archive_members=len(members),
        native_compiler_actions=18, separately_counted_driver_plans=3, auditor_compiler_actions=0,
        comparisons=pairs, sampled_profiles=samples, sample_totals=dict(totals),
        samples=sum(totals.values()), status_object_stdout_pairs=9, literal_stream_pairs=0,
        scope='Independent framing, byte and control audit. Samples select candidates; they do not certify code dependencies, complete calls, cache speedup or noninterference.',
        complete_closure_certified=False, substantial_novelty_established=False)
    (root / 'independent-sample-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    print(json.dumps({k: audit[k] for k in ('native_compiler_actions', 'samples', 'sample_totals', 'status_object_stdout_pairs')}))


if __name__ == '__main__': main(Path(sys.argv[1]))
