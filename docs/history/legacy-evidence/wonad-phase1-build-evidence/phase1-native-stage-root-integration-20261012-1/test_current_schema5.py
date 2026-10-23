"""Current integrated source/method tests; no live staging/build/keys or guests."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path('/u/elric/tree/wonad')
HERE=Path(__file__).resolve().parent
CANDIDATE=ROOT
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'android/tools'))

def candidate(name, relative):
    """Execute exact candidate methods with only repository data ROOT rebased.

    This partial overlay is not a live checkout; dependencies are current host
    helpers, not an executable stage deployment. No candidate main is invoked.
    """
    path=CANDIDATE/relative
    source=path.read_text()
    needle='ROOT = Path(__file__).resolve().parents[2]'
    if needle in source:
        assert source.count(needle)==1
        source=source.replace(needle,'ROOT = Path("/u/elric/tree/wonad")',1)
    module=type(sys)(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(source,str(path),'exec'),module.__dict__)
    return module

S=candidate('stage_contract','android/tools/stage_contract.py')
P=candidate('phase1_provenance','android/tools/phase1_provenance.py')
X=candidate('x86_build_comparison','android/tools/x86_build_comparison.py')
R=candidate('release_receipt','android/tools/release_receipt.py')
F=candidate('frankel_build_comparison','android/tools/frankel_build_comparison.py')
O=candidate('external_stage_os','android/platform/stage-os.py')
I=candidate('external_release_index','android/tools/phase1_release_index.py')
LOCK=json.loads((ROOT/'android/grapheneos.lock.json').read_text())

class Registry:
    def __enter__(self):
        self.temp=tempfile.TemporaryDirectory(prefix='wonad-native-schema5-host-')
        self.root=Path(self.temp.name);self.patches=[]
        definitions={'FRAMEWORK_PATCH_NAMES':('base.patch',),'LAUNCHER_PATCH_NAMES':('launcher.patch',),
                     'EMULATOR_PATCH_NAMES':('emulator.patch',),'NATIVE_PATCH_NAMES':('native-first.patch','native-second.patch')}
        for field,names in definitions.items():
            for name in names:
                target={'base.patch':'base.txt','launcher.patch':'launcher.txt','emulator.patch':'emulator.txt'}.get(name,'dispatcher/Entry.h')
                (self.root/name).write_text('--- a/'+target+'\n+++ b/'+target+'\n')
            self.patches.append(mock.patch.object(S,field,names))
        self.patches += [mock.patch.object(S,'PATCH_ROOT',self.root),mock.patch.object(S,'tool_ledger',return_value={'synthetic-tool':'a'*64})]
        for patch in self.patches:patch.start()
        return self
    def marker(self):
        value={field:'1'*40 for path,names,field in S.platform_lanes().values()}
        value.update(schema=S.stage_schema(),signer_sha256='2'*64,signer_certificate={},files={'public.der':'3'*64},
                     patches={label:S.patch_ledger(names) for label,(path,names,field) in S.platform_lanes().items()},
                     platform_targets={label:{name:'4'*64 for name in S.patch_target_names(names)}
                                       for label,(path,names,field) in S.platform_lanes().items()},tools=S.tool_ledger())
        value['frameworks_native_revision']=S.NATIVE_MANIFEST_REVISION
        return value
    def __exit__(self,*args):
        for patch in reversed(self.patches):patch.stop()
        self.temp.cleanup()

class NativeStageTests(unittest.TestCase):
    def test_actual_unchanged_lock_and_authenticated_manifest_pin(self):
        raw=(ROOT/'android/grapheneos.lock.json').read_bytes()
        self.assertEqual('ad259dde404f13a9d24e394b6ef8b19301ae436071316867ef1219e98f7486d6',hashlib.sha256(raw).hexdigest())
        source=Path('/u/elric/tree/wonad-grapheneos-2026100600')
        self.assertEqual(S.NATIVE_MANIFEST_REVISION,S.authenticated_native_revision(source,LOCK))

    def test_revision_reader_uses_locked_commit_not_native_head(self):
        payload=(Path('/u/elric/tree/wonad-grapheneos-2026100600')/'.repo/manifests/default.xml').read_bytes()
        seen=[]
        def git(argv,**kw):
            seen.append(argv)
            if 'show' in argv:return payload
            if argv[-1]=='refs/tags/2026100600':return (LOCK['manifest']['tag_object']+'\n').encode()
            return (LOCK['manifest']['commit']+'\n').encode()
        with mock.patch.object(S.subprocess,'check_output',side_effect=git):
            self.assertEqual(S.NATIVE_MANIFEST_REVISION,S.authenticated_native_revision(Path('/u/elric/tree/wonad-grapheneos-2026100600'),LOCK))
        self.assertTrue(all('/.repo/manifests' in row[2] for row in seen))
        self.assertIn(LOCK['manifest']['commit']+':default.xml',[row[-1] for row in seen])

    def test_bad_manifest_hash_duplicate_native_missing_wrong_revision_rejected(self):
        raw=(Path('/u/elric/tree/wonad-grapheneos-2026100600')/'.repo/manifests/default.xml').read_bytes()
        with self.assertRaises(ValueError):S.native_revision_from_payload(raw+b'\n',LOCK)
        template='<manifest>{}</manifest>'
        row='<project path="frameworks/native" name="platform_frameworks_native" remote="grapheneos" revision="'+S.NATIVE_MANIFEST_REVISION+'"/>'
        for text in (template.format(row+row),template.format(''),template.format(row.replace(S.NATIVE_MANIFEST_REVISION,'f'*40))):
            payload=text.encode();lock={'manifest':{'default_xml_size':len(payload),'default_xml_sha256':hashlib.sha256(payload).hexdigest()}}
            with self.assertRaises(ValueError):S.native_revision_from_payload(payload,lock)

    def test_registered_nonempty_requires5_empty_requires4_no_fallback(self):
        self.assertEqual(4,S.stage_schema())
        with Registry() as registry:
            marker=registry.marker();S.require_stage_schema(marker);self.assertEqual(5,S.stage_schema())
            for schema in (4,5.0,True):
                bad=copy.deepcopy(marker);bad['schema']=schema
                with self.assertRaises(ValueError):S.require_stage_schema(bad)
        with self.assertRaises(ValueError):S.require_stage_schema({'schema':5})
        with self.assertRaises(ValueError):S.require_stage_schema({'schema':4,'frameworks_native_revision':S.NATIVE_MANIFEST_REVISION})

    def test_native_missing_lane_pin_order_digest_tool_and_extra_target_rejected(self):
        with Registry() as registry:
            good=registry.marker();S.marker_owned_targets(good)
            cases=[]
            bad=copy.deepcopy(good);del bad['platform_targets']['frameworks_native'];cases.append(bad)
            bad=copy.deepcopy(good);bad['frameworks_native_revision']='f'*40;cases.append(bad)
            bad=copy.deepcopy(good);bad['patches']['frameworks_native'].reverse();cases.append(bad)
            bad=copy.deepcopy(good);bad['patches']['frameworks_native'][0]['sha256']='f'*64;cases.append(bad)
            bad=copy.deepcopy(good);bad['tools']={'foreign':'a'*64};cases.append(bad)
            bad=copy.deepcopy(good);bad['platform_targets']['frameworks_native']['unowned.cpp']='f'*64;cases.append(bad)
            bad=copy.deepcopy(good);bad['platform_targets']['frameworks_native']={};cases.append(bad)
            bad=copy.deepcopy(good);bad['extra']='ignored';cases.append(bad)
            for bad in cases:
                with self.assertRaises(ValueError):S.marker_owned_targets(bad)

    def test_x86_native_exact_tracked_or_generated_partition(self):
        with Registry() as registry:
            marker=registry.marker();owned=X.marker_owned_targets(marker);self.assertIn('frameworks/native/dispatcher/Entry.h',owned)
            generated={name:{} for name in X.marker_external_inputs(marker)}
            X.validate_custom_stage_inventory(marker,{name:{} for name in owned},generated)
            native='frameworks/native/dispatcher/Entry.h'
            changed={name:{} for name in owned if name!=native};untracked=dict(generated,**{native:{}})
            X.validate_custom_stage_inventory(marker,changed,untracked)
            for c,g in ((changed,generated),(dict(changed,**{'frameworks/native/foreign.cpp':{}}),untracked)):
                with self.assertRaises(X.ComparisonError):X.validate_custom_stage_inventory(marker,c,g)

    def test_provenance_owned_targets_include_native_and_updater_without_source_walk(self):
        with Registry() as registry,mock.patch.object(P,'load_json',return_value=registry.marker()):
            owned=P.owned_targets(Path('/synthetic-unopened-source'))
            self.assertIn('frameworks/native/dispatcher/Entry.h',owned)
            self.assertIn('packages/apps/Updater/res/values/config.xml',owned)

    def test_project_ledger_missing_duplicate_foreign_revision_rejected(self):
        row={'path':'frameworks/native','name':'platform_frameworks_native','remote':'grapheneos','revision':S.NATIVE_MANIFEST_REVISION}
        self.assertEqual(S.NATIVE_MANIFEST_REVISION,S.native_revision_from_projects([row]))
        for rows in ([],[row,row],[dict(row,revision='f'*40)]):
            with self.assertRaises(ValueError):S.native_revision_from_projects(rows)

    def test_aggregate_native_active_state_and_old4_rejection(self):
        with Registry() as registry:
            marker=registry.marker();signer=marker['signer_sha256']
            x={'source':{'stage':{'state':'schema-5-owned-stage','qualification':'emulator-development-only',
                                'marker':marker,'development_certificate':{'der_sha256':signer}}}}
            arm={'source':{'stage':{'state':'schema-5-with-project-updater','marker':marker,'signer':{'der_sha256':signer}}}}
            self.assertEqual(signer,I.x86_stage(x)[1]);self.assertEqual(signer,I.arm_stage(arm)[1])
            x['source']['stage']['state']='schema-4-owned-stage'
            with self.assertRaises(I.IndexError):I.x86_stage(x)

    def test_stage_targets_still_reject_symlinked_ancestor(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);(path/'real').mkdir();(path/'real/file').write_text('public');(path/'linked').symlink_to(path/'real')
            with self.assertRaisesRegex(ValueError,'symlinked'):O.verify_targets(path,{'linked/file':hashlib.sha256(b'public').hexdigest()},'native')

    def test_release_marker_schema5_native_lane_exact_full_target_bytes(self):
        with Registry() as registry:
            source=registry.root/'os';(source/'.repo').mkdir(parents=True)
            public=b'public-certificate-placeholder-not-a-key'*8
            target=source/'external/wonad';target.mkdir(parents=True);(target/'WonadReleaseCertificate.der').write_bytes(public)
            digest=hashlib.sha256(public).hexdigest();marker=registry.marker()
            marker.update(signer_sha256=digest,files={'WonadReleaseCertificate.der':digest},
                          signer_certificate={'path':'WonadReleaseCertificate.der','sha256':digest,'size':len(public)})
            for label,(project,names,field) in S.platform_lanes().items():
                if label!='frameworks_native':marker[field]=LOCK[label]['commit']
                for name in marker['platform_targets'][label]:
                    file=source/project/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(b'exact-native-or-platform-post-bytes')
                    marker['platform_targets'][label][name]=hashlib.sha256(file.read_bytes()).hexdigest()
            (target/'.wonad-stage.json').write_text(json.dumps(marker))
            with mock.patch.object(S,'authenticated_native_revision',return_value=S.NATIVE_MANIFEST_REVISION):
                stage=R.read_stage_marker(source,LOCK)
                self.assertEqual(5,stage['schema']);self.assertEqual(S.NATIVE_MANIFEST_REVISION,stage['frameworks_native_revision'])
                native=source/'frameworks/native/dispatcher/Entry.h';native.write_bytes(b'edited')
                with self.assertRaises(R.ReceiptError):R.read_stage_marker(source,LOCK)

    def test_release_native_source_pin_must_come_from_authenticated_manifest(self):
        with (Registry(),mock.patch.object(S,'authenticated_native_revision',return_value=S.NATIVE_MANIFEST_REVISION),
             mock.patch.object(R,'revision',side_effect=lambda repo: S.NATIVE_MANIFEST_REVISION if repo.name=='native' else next(
                 LOCK[key]['commit'] for key,path in [('manifest','.repo/manifests'),('frameworks_base','frameworks/base'),
                 ('launcher3','packages/apps/Launcher3'),('updater','packages/apps/Updater'),('emulator_goldfish','device/generic/goldfish')]
                 if str(repo).endswith(path)))):
            pins=R.verify_source_pins(Path('/synthetic-unopened-source'),LOCK)
            self.assertEqual({'commit':S.NATIVE_MANIFEST_REVISION,'manifest_path':'frameworks/native'},pins['frameworks_native'])

    def test_frankel_native_partition_rejects_missing_extra_or_relabelled_target(self):
        with Registry() as registry:
            marker=registry.marker();owned=X.marker_owned_targets(marker)
            changed={name:{'sha256':digest} for name,digest in owned.items()}
            changed['packages/apps/Updater/res/values/config.xml']={'sha256':'5'*64}
            generated={name:{'sha256':'6'*64} for name in X.marker_external_inputs(marker)}
            generated['.wonad-updater-stage.json']={'sha256':'7'*64}
            generated['vendor/google_devices/frankel/AndroidProducts.mk']={'sha256':'8'*64}
            row={'path':'frameworks/native','name':'platform_frameworks_native','remote':'grapheneos','revision':S.NATIVE_MANIFEST_REVISION}
            materials={'frameworks/native':{'gitlinks':{},'materialized_eol':{},'materialized_lfs':{}}}
            source={'pin':{'projects':[row],'project_count':1},'vendor':{'files':{'AndroidProducts.mk':{}}},
                    'stage':{'state':'schema-5-with-project-updater','marker':marker,'updater':{'configured_sha256':'5'*64}},
                    'owned_tracked_changes':changed,'generated_inputs':generated,
                    'worktree_materializations':materials,'worktree_materializations_sha256':F.canonical_digest(materials)}
            F.validate_source_materializations(source)
            native='frameworks/native/dispatcher/Entry.h'
            for field,modify in [('owned_tracked_changes',lambda rows:rows.pop(native)),
                                 ('owned_tracked_changes',lambda rows:rows.update({'frameworks/native/foreign.cpp':{'sha256':'4'*64}})),
                                 ('generated_inputs',lambda rows:rows.update({'frameworks/native/foreign.cpp':{'sha256':'4'*64}}))]:
                bad=copy.deepcopy(source);modify(bad[field])
                with self.assertRaises(F.ComparisonError):F.validate_source_materializations(bad)
            bad=copy.deepcopy(source);bad['pin']['projects'][0]['revision']='f'*40
            with self.assertRaises(ValueError):F.validate_source_materializations(bad)

    def test_native_complete_post_target_plan_and_independent_edit_rejection(self):
        with tempfile.TemporaryDirectory(prefix='wonad-native-postbytes-host-') as temporary:
            root=Path(temporary);repo=root/'repo';repo.mkdir();file=repo/'Entry.h';file.write_text('before\n')
            def git(*args):
                subprocess.run(['git','-C',str(repo),*args],check=True,capture_output=True)
            git('init','--quiet');git('add','Entry.h')
            git('-c','user.name=Host Fixture','-c','user.email=fixture@invalid','commit','--quiet','-m','Synthetic target')
            patch=root/'synthetic-native.patch'
            patch.write_text('diff --git a/Entry.h b/Entry.h\n--- a/Entry.h\n+++ b/Entry.h\n@@ -1 +1 @@\n-before\n+after\n')
            changes=O.framework_plan(repo,[patch])
            self.assertEqual([(file,b'before\n',b'after\n')],changes)
            self.assertEqual({'Entry.h':hashlib.sha256(b'after\n').hexdigest()},O.target_hashes(repo,[patch],changes))
            file.write_text('independent\n')
            with self.assertRaisesRegex(ValueError,'independently modified'):O.framework_plan(repo,[patch])

    def test_every_external_candidate_is_python_parseable_without_writing_bytecode(self):
        paths=list((CANDIDATE/'android/tools').glob('*.py'))+[CANDIDATE/'android/platform/stage-os.py']
        for path in paths:compile(path.read_bytes(),str(path),'exec')

if __name__=='__main__':unittest.main(verbosity=2)
