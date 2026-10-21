"""Real ccache baseline for recipient-local warning policies, Modal only."""
import json
import shlex
import sys
import tarfile
from pathlib import Path

import modal
from modal_rgec_native import execute, sha, write

URL = 'https://github.com/ccache/ccache/releases/download/v4.14.1/ccache-4.14.1-linux-x86_64-musl-static.tar.gz'
RELEASE_SHA = '8f684cf82a7acd2f1daddbefcda505c499afe8245cfbfe78f751ce389cd6df52'
HELPERS = ['scripts/rgec_residual_probe.py', 'scripts/rgec_backend_probe.py',
    'scripts/rgec_native_effect_probe.py', 'scripts/rgec_native_event_probe.py',
    'src/unauthorized_channels/modal_recipient_entry.py']
BUILD = """import hashlib,io,tarfile,urllib.request
data=urllib.request.urlopen(%r,timeout=120).read()
assert hashlib.sha256(data).hexdigest()==%r
open('/ccache-release.tar.gz','wb').write(data)
t=tarfile.open(fileobj=io.BytesIO(data));m=[x for x in t if x.isfile() and x.name.endswith('/ccache')]
assert len(m)==1
open('/ccache-baseline','wb').write(t.extractfile(m[0]).read())
import os
os.chmod('/ccache-baseline',0o555)
""" % (URL, RELEASE_SHA)
PROBE = """import collections,json,os,shutil,sys
sys.path.insert(0,'/')
from rgec_residual_probe import request,save
from rgec_backend_probe import ROOT,run,queue_signature
from rgec_native_effect_probe import FLAGS,sha,signature
from modal_recipient_entry import ENV
os.mkdir(ROOT);os.chown(ROOT,65534,65534)
result={'cases':[],'tool_sha256':{p:sha(open(p,'rb').read()) for p in ('/ccache-baseline','/usr/local/bin/clang')},
 'ccache_release_sha256':sha(open('/ccache-release.tar.gz','rb').read()),'production_policy':False}
status,out,error=run(['/ccache-baseline','--version'],'/src/zlib');assert status==0,error
result['ccache_version']=out.decode();save('ccache-version.stdout',out)
status,_,error=run(['/usr/local/bin/clang']+FLAGS+['-fPIC','-c','deflate.c','-o',ROOT+'/prior.o'],'/src/zlib')
assert status==0,error
prior=open(ROOT+'/prior.o','rb').read()
for mode in ('default','preprocessor'):
 for source_path in ('/src/zlib/adler32.c','/src/zlib/deflate.c','/src/libfuzzer/FuzzerUtil.cpp'):
  cwd,source=os.path.dirname(source_path),os.path.basename(source_path)
  original=open(source_path,'rb').read();original_stat=os.stat(source_path)
  compiler='/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang'
  flags=FLAGS+(['-stdlib=libc++','-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])+['-Wframe-larger-than=1']
  cache='/workspace/ccache-'+mode+'-'+source
  os.mkdir(cache);os.chown(cache,65534,65534)
  config=ROOT+'/'+mode+'-'+source+'.conf'
  open(config,'w').write('compiler_check = content\\ndirect_mode = '+('false' if mode=='preprocessor' else 'true')+'\\n')
  ENV.update(CCACHE_DIR=cache,CCACHE_CONFIGPATH=config)
  def stats(label):
   status,out,error=run(['/ccache-baseline','--print-stats'],cwd);assert status==0,error
   save(label+'.stats',out)
   return {line.split()[0]:int(line.split()[1]) for line in out.decode().splitlines()}
  try:
   for step,policy in enumerate(('error','warning','ignored','warning','error','ignored')):
    label=mode+'-'+source+'-'+str(step)+'-'+policy
    data=b'#pragma clang diagnostic push\\n'+('#pragma clang diagnostic '+policy.ljust(7)+' "-Wframe-larger-than="\\n').encode()+original+b'\\n#pragma clang diagnostic pop\\n'
    open(source_path,'wb').write(data);os.utime(source_path,(1641013200,1641013200));save(label+'.source',data)
    case={'source':source,'cwd':cwd,'compiler':compiler,'flags':flags,'name':label+'-reference'}
    native=request(case,'native',prior)
    before=stats(label+'-before');ENV['CCACHE_LOGFILE']=ROOT+'/'+label+'.ccache.log'
    cached=request(dict(case,name=label+'-cached',compiler='/ccache-baseline',flags=[compiler]+flags),'native',prior)
    after=stats(label+'-after')
    result['cases'].append({'name':label,'mode':mode,'policy':policy,'native':native,'cached':cached,
     'status_and_streams_match':all(native[k]==cached[k] for k in ('returncode','stdout_sha256','stderr_sha256')),
     'object_bytes_match':native['object_sha256']==cached['object_sha256'],
     'structural_effects_match':signature(native)==signature(cached),
     'queued_event_roles_match':queue_signature(native['events'])==queue_signature(cached['events']),
     'stats_delta':{k:after[k]-before.get(k,0) for k in after if after[k]!=before.get(k,0)}})
    open(ROOT+'/evidence.json','w').write(json.dumps(result,indent=2))
    print(label,json.dumps(result['cases'][-1]['stats_delta']),flush=True)
  finally:
   open(source_path,'wb').write(original);os.utime(source_path,ns=(original_stat.st_atime_ns,original_stat.st_mtime_ns))
"""


def main(root):
    prior = json.loads(Path('runs/rgec-modal-residual-state-2026-10-04-v9/evidence.json').read_text())
    root.mkdir(parents=True, exist_ok=False)
    paths = [Path(__file__), Path('modal_rgec_native.py')] + [Path(p) for p in HELPERS]
    evidence = {'date': '2026-10-04', 'platform': 'Modal', 'gpu': None, 'cpu': 2,
        'memory_mib': 4096, 'source_sha256': {str(p): sha(p.read_bytes()) for p in paths},
        'release_url': URL, 'release_sha256': RELEASE_SHA, 'sandboxes': []}
    for path in paths: (root / path.name).write_bytes(path.read_bytes())
    image = modal.Image.from_id(prior['sandboxes'][0]['image_id']).run_commands(
        '/usr/bin/python3 -I -c ' + shlex.quote('exec(' + repr(BUILD) + ')'))
    app = modal.App('rgec-ccache-diagnostic-policy-baseline'); sandbox = None
    try:
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
                cpu=2, memory=4096, timeout=1200, block_network=True)
            entry = {'phase': 'baseline', 'id': sandbox.object_id, 'image_id': image.object_id}
            evidence['sandboxes'].append(entry)
            for path in paths[2:]: write(sandbox, '/' + path.name, path.read_bytes())
            write(sandbox, '/baseline-probe.py', PROBE.encode()); (root / 'baseline-probe.py').write_text(PROBE)
            code, out, error = execute(sandbox, '/usr/bin/python3', '-I', '/baseline-probe.py', timeout=1000)
            entry['returncode'] = code
            (root / 'baseline.stdout').write_bytes(out); (root / 'baseline.stderr').write_bytes(error)
            from modal_rgec_residual import collect
            entry['raw_archive_sha256'] = collect(sandbox, root, 'baseline')
            assert code == 0, error[-2500:]
    except Exception as error:
        evidence['error'] = str(error); raise
    finally:
        if sandbox:
            sandbox.terminate()
            try: sandbox.wait()
            except modal.exception.SandboxTerminatedError: pass
            evidence['sandboxes'][0]['cleanup_returncode'] = sandbox.returncode
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main(Path(sys.argv[1]))
