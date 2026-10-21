"""Unmodified complete zlib native build, upstream tests and real-file data."""
import json
import os
import resource
import shlex
import shutil
import subprocess
import sys
import time

sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop
from rgec_backend_probe import ROOT
from rgec_native_effect_probe import FLAGS, sha


def main(mode=None):
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    project = ROOT + '/project'
    shutil.copytree('/src/zlib', project, ignore=shutil.ignore_patterns('.git', '*.o', '*.a',
        '*.so', '*.so.*', 'example', 'minigzip', 'example64', 'minigzip64'))
    for directory, folders, files in os.walk(project):
        os.chown(directory, 65534, 65534)
        for name in files: os.chown(directory + '/' + name, 65534, 65534)
    result = {'phases': [], 'roundtrips': [], 'cpu': 2, 'gpu': None,
        'scope': 'Fresh complete authentic zlib source tree, native configure/make/test and compression of real repository files; no synthetic functions/data.',
        'shared_reuse_enabled': False, 'noninterference_certified': False}
    broker = None
    artifact = ROOT
    if mode:
        os.chown(ROOT, 0, 0)
        artifact = '/rgec-private/zlib'
        os.makedirs(artifact, mode=0o700)
        result['artifact_directory'] = artifact
        from rgec_zlib_compiler_broker import CompilerBroker
        broker = CompilerBroker(project, mode, result).start()
        result['shared_reuse_enabled'] = mode in ('replay','local-warm')
        result['experimental_fixed_workflow'] = True
    def save(name, data):
        with open(artifact+'/'+name, 'wb') as stream: stream.write(data)
        return sha(data)
    originals = {}
    for directory, folders, files in os.walk(project):
        for name in files:
            if name.endswith(('.c','.h')) or name in ('configure','Makefile.in','README'):
                path = directory+'/'+name; relative = os.path.relpath(path, project)
                data = open(path,'rb').read(); originals[relative] = data
                result.setdefault('input_sha256',{})[relative] = save('input-'+relative.replace('/','__'),data)
    env = dict(ENV, CC='/usr/local/bin/clang', CFLAGS=' '.join(shlex.quote(flag) for flag in FLAGS+['-fPIC']))
    result['environment'] = env
    def command(label, argv, contents=None):
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        self_before = resource.getrusage(resource.RUSAGE_SELF); start = time.monotonic()
        process = subprocess.Popen(argv, cwd=project, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop, close_fds=True)
        out,error=process.communicate(contents,timeout=3600 if mode and label=='build' else 600)
        after=resource.getrusage(resource.RUSAGE_CHILDREN)
        self_after=resource.getrusage(resource.RUSAGE_SELF)
        row={'label':label,'argv':argv,'returncode':process.returncode,
            'child_cpu_seconds':(after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime),
            'broker_self_cpu_seconds':(self_after.ru_utime+self_after.ru_stime)-(self_before.ru_utime+self_before.ru_stime),
            'helper_wall_seconds':time.monotonic()-start,
            'stdout_sha256':save(label+'.stdout',out),'stderr_sha256':save(label+'.stderr',error)}
        result['phases'].append(row)
        print(json.dumps({'phase':'command','label':label,'returncode':process.returncode}),flush=True)
        return row,out,error
    try:
        build = ['/usr/bin/make','-j1','CC=/rgec-zlib-compiler'] if mode else ['/usr/bin/make','-j2']
        for label,argv in (('configure',['./configure','--static']),('build',build),
                           ('upstream-test',['/usr/bin/make','test'])):
            row,out,error=command(label,argv)
            assert row['returncode']==0,(label,error[-4000:],out[-4000:])
        for path in ('/src/zlib/README','/src/zlib/zlib.h','/src/libfuzzer/FuzzerUtil.cpp'):
            original=open(path,'rb').read();label=os.path.basename(path)
            input_sha=save('roundtrip-'+label+'.input',original)
            encoded,compressed,error=command('compress-'+label,['./minigzip'],original)
            assert encoded['returncode']==0,error
            decoded,restored,error=command('decompress-'+label,['./minigzip','-d'],compressed)
            row={'path':path,'input_sha256':input_sha,'input_bytes':len(original),
                'compressed_bytes':len(compressed),'decoded_sha256':sha(restored),
                'bytes_equal':original==restored,'compress_returncode':encoded['returncode'],
                'decompress_returncode':decoded['returncode']}
            result['roundtrips'].append(row)
            assert decoded['returncode']==0 and row['bytes_equal'],row
        result['source_bodies_unchanged']=all(open(project+'/'+name,'rb').read()==data
            for name,data in originals.items() if name.endswith(('.c','.h')) and name!='zconf.h')
        assert result['source_bodies_unchanged']
        result['outputs']={}
        for directory,folders,files in os.walk(project):
            for name in files:
                if name.endswith(('.o','.a')) or name in ('example','minigzip','example64','minigzip64','Makefile','zconf.h'):
                    path=directory+'/'+name;relative=os.path.relpath(path,project);data=open(path,'rb').read()
                    result['outputs'][relative]={'bytes':len(data),'sha256':save('output-'+relative.replace('/','__'),data)}
        assert 'libz.a' in result['outputs'] and len([name for name in result['outputs'] if name.endswith('.o')])>=15
    finally:
        if broker: broker.stop()
        with open(artifact+'/evidence.json','w') as stream:json.dump(result,stream,indent=2)


if __name__=='__main__':main(sys.argv[1] if len(sys.argv)>1 else None)
