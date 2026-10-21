"""Independently inspect retained complete native builds and authenticated tapes."""
import collections
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import struct
import sys
import tarfile


def sha(data): return hashlib.sha256(data).hexdigest()


root=Path(sys.argv[1]);manifest=json.loads((root/'evidence.json').read_text())
counts=collections.Counter();phases={}
for path,expected in manifest['source_sha256'].items():
    assert sha((root/Path(path).name).read_bytes())==expected
    counts['frozen_source_snapshots']+=1
reference_bytes=(root/'native-reference-build.stdout').read_bytes()
assert sha(reference_bytes)==manifest['native_commands_source_sha256']
commands=[shlex.split(line)[1:] for line in reference_bytes.decode().splitlines()
          if line.startswith('/usr/local/bin/clang ')]
assert commands==manifest['native_commands'] and len(commands)==23
assert sum('-c' in args for args in commands)==19
assert sha((root/'native-reference-manifest.json').read_bytes())==manifest['native_reference_manifest_sha256']
assert json.loads((root/'zlib-native-commands.json').read_text())==commands
spec=importlib.util.spec_from_file_location('frozen_store',root/'backend_recipe_store.py')
store=importlib.util.module_from_spec(spec);spec.loader.exec_module(store)


def checked(folder,name,expected):
    data=(folder/name).read_bytes();assert sha(data)==expected,name
    counts['recorded_raw_hashes']+=1;return data


for sandbox in manifest['sandboxes']:
    assert sandbox['cleanup_returncode']==137 and sandbox['returncode']==0
    assert sandbox['tool_sha256']==manifest['tool_sha256']
    if sandbox['role']=='separate-full-project-producer':continue
    folder=root/sandbox['phase'];phases[sandbox['phase']]=data=json.loads((folder/'evidence.json').read_text())
    checked(folder,'raw.tar.gz',sandbox['raw_archive_sha256'])
    with tarfile.open(folder/'raw.tar.gz') as stream:
        for member in stream:
            assert member.isfile() and member.name=='raw/'+Path(member.name).name
            assert stream.extractfile(member).read()==(folder/Path(member.name).name).read_bytes()
            counts['archive_members']+=1
    assert data['source_bodies_unchanged'] and len(data['phases'])==9
    assert data['experimental_fixed_workflow'] and data['environment']['CC']=='/usr/local/bin/clang'
    assert data['phases'][1]['argv']==['/usr/bin/make','-j1','CC=/rgec-zlib-compiler']
    assert data['phases'][0]['argv']==['./configure','--static']
    assert data['phases'][2]['argv']==['/usr/bin/make','test']
    assert '-fsanitize=address' in data['environment']['CFLAGS'] and 'ASAN_OPTIONS' not in data['environment']
    for relative,expected in data['input_sha256'].items():checked(folder,'input-'+relative.replace('/','__'),expected)
    for phase in data['phases']:
        assert phase['returncode']==0 and phase['child_cpu_seconds']>=0 and phase['helper_wall_seconds']>0
        checked(folder,phase['label']+'.stdout',phase['stdout_sha256'])
        checked(folder,phase['label']+'.stderr',phase['stderr_sha256'])
        counts['native_phases_completed']+=1
    upstream=(folder/'upstream-test.stdout').read_bytes()
    assert b'*** zlib test OK ***' in upstream and b'*** zlib 64-bit test OK ***' in upstream
    for roundtrip in data['roundtrips']:
        name=Path(roundtrip['path']).name
        original=checked(folder,'roundtrip-'+name+'.input',roundtrip['input_sha256'])
        compressed=(folder/('compress-'+name+'.stdout')).read_bytes()
        restored=(folder/('decompress-'+name+'.stdout')).read_bytes()
        assert original==restored==gzip.decompress(compressed)
        assert sha(restored)==roundtrip['decoded_sha256'] and roundtrip['bytes_equal']
        assert len(original)==roundtrip['input_bytes'] and len(compressed)==roundtrip['compressed_bytes']
        counts['actual_repository_roundtrips']+=1
    assert len(data['compiler_actions'])==23
    assert sorted(row['arguments'] for row in data['compiler_actions'])==sorted(commands)
    for action in data['compiler_actions']:
        assert action['returncode']==0 and action['is_compile']==('-c' in action['arguments'])
        label=action['label']
        control=checked(folder,label+'.control',action['control_sha256'])
        stdout=checked(folder,label+'.stdout',action['stdout_sha256'])
        checked(folder,label+'.stderr',action['stderr_sha256'])
        checked(folder,label+'.output',action['output_sha256'])
        counts['actual_compiler_and_link_actions']+=1
        if action['query_emitted']:
            query=checked(folder,label+'.query',action['query_sha256'])
            size=struct.unpack_from('<Q',control,6)[0]
            assert control[:6]==b'RGECQ1' and query==control[14:14+size]
            assert control[14+size:]==action['receipt'].encode()==b'RGECH1'
            reply=checked(folder,label+'.reply',action['reply_sha256'])
            assert store.packet_key(reply)==store.computation_key(query)
            assert reply[:6]==b'RGECB3' and not stdout
            counts['authenticated_query_packet_bindings']+=1
        else:
            assert not action['receipt'] and control==stdout
    for relative,record in data['outputs'].items():
        raw=checked(folder,'output-'+relative.replace('/','__'),record['sha256']);assert len(raw)==record['bytes']
        if relative.endswith('.o'):assert raw[:4]==b'\x7fELF';counts['native_objects']+=1
        if relative in ('example','example64','minigzip','minigzip64'):assert raw[:4]==b'\x7fELF';counts['native_executables']+=1
        if relative=='libz.a':assert raw[:8]==b'!<arch>\n';counts['native_archives']+=1
assert set(phases)=={'native','wrapped-cold','policy-cold','policy-peer-warm'}
for role,data in phases.items():
    native=phases['native']
    assert data['outputs']==native['outputs'] and data['input_sha256']==native['input_sha256']
    assert data['roundtrips']==native['roundtrips']
    for actual,reference in zip(data['phases'],native['phases']):
        assert all(actual[key]==reference[key] for key in ('returncode','stdout_sha256','stderr_sha256'))
    for actual,reference in zip(data['compiler_actions'],native['compiler_actions']):
        assert all(actual[key]==reference[key] for key in ('arguments','returncode','stdout_sha256','stderr_sha256','output_sha256'))
        def structural(row):
            result={key:value for key,value in row['after'].items() if key not in ('ino','mtime_ns','ctime_ns')}
            result['inode_changed']=row['before'].get('ino')!=row['after'].get('ino')
            return result
        assert structural(actual)==structural(reference)
        # Preserve every raw filename/cookie; compare the established limited role projection.
        def roles(row):
            return [(event['mask'],'temporary' if event['name'].endswith('.tmp') else event['name']) for event in row['events']]
        assert roles(actual)==roles(reference),(role,actual['label'],'events')
        counts['native_compiler_effect_comparisons']+=role!='native'
    assert sum(action['query_emitted'] for action in data['compiler_actions'])==(19 if role.startswith('policy-') else 0)
for entry in manifest['store_audit']:
    if entry['route']=='authenticated-hit':counts['authenticated_hits']+=1;continue
    assert entry['route']=='separate-producer-miss'
    origin=entry['origin'];folder=root/origin['sandbox_id']
    frozen=json.loads((folder/'origin.json').read_text());assert frozen==origin
    bound=checked(folder,'producer.key',origin['captured_context_sha256'])
    packet=checked(folder,'producer.packet',origin['packet_sha256'])
    assert origin['returncode']==0 and origin['reusable'] and origin['protected_files']>0
    assert origin['fresh_frontend_returncode']==1 and not origin['fresh_frontend_packet']
    assert not (folder/'fresh.control').read_bytes() and (folder/'fresh.stderr').read_bytes()
    assert packet[:6]==b'RGECB2' and store.packet_key(packet)==store.computation_key(bound)
    full_size=struct.unpack_from('<Q',packet,6)[0];assert packet[14:14+full_size]==bound
    delivery=b'RGECB3'+packet[14+full_size:]
    action=next(row for row in phases['policy-cold']['compiler_actions']
        if row.get('query_sha256')==sha(bound))
    assert (root/'policy-cold'/(action['label']+'.reply')).read_bytes()==delivery
    assert sha((folder/'producer.object').read_bytes())==action['output_sha256']
    offset=14+struct.unpack_from('<Q',delivery,6)[0]
    def number():
        global offset
        value=struct.unpack_from('<Q',delivery,offset)[0];offset+=8;return value
    def field():
        global offset
        length=number();value=delivery[offset:offset+length];offset+=length;assert len(value)==length;return value
    assert number()==1
    for _ in range(number()):number();number();field();field()
    output=bytearray()
    for _ in range(number()):
        kind,position,contents=number(),number(),field()
        if kind==0:output.extend(contents)
        elif kind==1:
            assert position+len(contents)<=len(output);output[position:position+len(contents)]=contents
        else:assert kind in (5,6,8,9),kind
    assert offset==len(delivery) and bytes(output)==(folder/'producer.object').read_bytes()
    counts['separate_native_producers']+=1
assert counts['separate_native_producers']==19 and counts['authenticated_hits']==19
assert counts['authenticated_query_packet_bindings']==38
result={'root':str(root),'manifest_sha256':sha((root/'evidence.json').read_bytes()),
    'counts':dict(counts),'complete_functional_suite':True,
    'limited_structural_and_event_projection':True,'adaptive_noninterference_proved':False,
    'build_child_cpu_seconds':{role:data['phases'][1]['child_cpu_seconds'] for role,data in phases.items()},
    'build_helper_wall_seconds':{role:data['phases'][1]['helper_wall_seconds'] for role,data in phases.items()}}
(root/'independent-full-zlib-store-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,indent=2))
