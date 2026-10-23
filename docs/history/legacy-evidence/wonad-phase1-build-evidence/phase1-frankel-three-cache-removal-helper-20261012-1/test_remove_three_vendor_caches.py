"""Hostile host fixtures/mock mutators only; never open/delete actual cache targets."""
import argparse
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import remove_three_vendor_caches as V

class CacheRemovalTests(unittest.TestCase):
    def args(self, flag=True):
        return argparse.Namespace(execute_after_explicit_cache_exception_and_root_review=flag,
                                  reviewed_helper_sha256='a'*64,authorization_sha256='b'*64)

    def auth(self):
        return {'schema':1,'kind':'phase1_exact_three_interrupted_vendor_cache_cleanup_authorization_v1',
            'user_exception':True,'scope':'discard_only_interrupted_extraction_bytes_preserve_all_other_custody',
            'targets':list(map(str,V.TARGETS)),'source':str(V.SOURCE),'audit_owner_sha256':V.OWNER_SHA,
            'helper_sha256':'a'*64,'host_tests_sha256':'c'*64}

    def test_exact_literal_three_work6_7_8_only_and_no_work5(self):
        self.assertEqual(3,len(V.TARGETS))
        for number,target in zip((6,7,8),V.TARGETS):
            self.assertEqual(V.BASE/f'phase1-frankel-vendor-cache-work-20261012-{number}/unpacked/frankel-CP3A.261005.005-tmp',target)
        self.assertNotIn('work-20261012-5',str(V.TARGETS))

    def test_missing_authority_flag_fails_before_file_lock_docker_or_mutation(self):
        with (mock.patch.object(V,'read_regular') as read,mock.patch.object(V.fcntl,'flock') as lock,
             mock.patch.object(V,'authenticated_inputs') as inputs,mock.patch.object(V.os,'unlink') as unlink,
             mock.patch.object(V.os,'rmdir') as rmdir):
            with self.assertRaises(ValueError):V.execute(self.args(False))
            for call in (read,lock,inputs,unlink,rmdir):call.assert_not_called()

    def test_malformed_review_hash_fails_before_authorization_io(self):
        for value in (None,'short','z'*64):
            args=self.args();args.reviewed_helper_sha256=value
            with mock.patch.object(V,'read_regular') as read,self.assertRaises(ValueError):V.authorization(args)
            read.assert_not_called()

    def test_exact_authorization_positive_reads_helper_and_host_test_hashes(self):
        with (mock.patch.object(V,'read_regular',return_value=(b'',{})) as read,
             mock.patch.object(V,'load',return_value=(self.auth(),{}))):
            V.authorization(self.args())
        self.assertEqual('a'*64,read.call_args_list[0].args[1])
        self.assertEqual('c'*64,read.call_args_list[1].args[1])

    def test_authorization_bool_foreign_target_scope_missing_pin_and_unknown_field_rejected(self):
        hostiles=[]
        for field,value in [('schema',True),('user_exception',False),('targets',list(reversed(list(map(str,V.TARGETS))))),
                            ('scope','delete-all-work'),('source','/'),('audit_owner_sha256','d'*64),
                            ('helper_sha256','d'*64)]:
            value_auth=self.auth();value_auth[field]=value;hostiles.append(value_auth)
        value_auth=self.auth();value_auth['extra']=True;hostiles.append(value_auth)
        value_auth=self.auth();del value_auth['targets'];hostiles.append(value_auth)
        for auth in hostiles:
            with mock.patch.object(V,'read_regular',return_value=(b'',{})),mock.patch.object(V,'load',return_value=(auth,{})),self.assertRaises(ValueError):
                V.authorization(self.args())

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):json.loads('{"a":1,"a":2}',object_pairs_hook=V.unique)

    def test_regular_reader_rejects_symlink_hardlink_and_wrong_hash(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);file=p/'file';file.write_text('public');link=p/'link';link.symlink_to(file)
            with self.assertRaises(OSError):V.read_regular(link)
            with self.assertRaises(ValueError):V.read_regular(file,'0'*64)
            os.link(file,p/'alias')
            with self.assertRaises(ValueError):V.read_regular(file)

    def test_parent_directory_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);(p/'real').mkdir();(p/'link').symlink_to(p/'real',target_is_directory=True)
            with self.assertRaises(OSError):V.opened_directory(p/'link')

    def test_mount_target_descendant_and_malformed_escapes_fail_but_ancestor_mount_is_normal(self):
        target=V.TARGETS[0]
        template='1 0 8:1 / {} rw - xfs /dev/test rw\n'
        V.no_mounted_targets(template.format('/u'),V.TARGETS)
        for point in (str(target),str(target/'child'),str(target)+'\\999'):
            with self.assertRaises(ValueError):V.no_mounted_targets(template.format(point),V.TARGETS)
        with self.assertRaises(ValueError):V.no_mounted_targets('garbage',V.TARGETS)

    def corpus(self,path):
        rows=[]
        for p in [path]+sorted(path.rglob('*')):
            row=V.metadata(p.lstat(),p);row['relative_path']=str(p.relative_to(path))
            if p.is_file() and not p.is_symlink():row['fiemap']={'test-fixture':True}
            if p.is_symlink():row['opaque_symlink_target']=os.readlink(p)
            rows.append(row)
        return rows

    def test_fd_census_exact_positive_and_opaque_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'cache';path.mkdir();(path/'data').write_text('public');(path/'outside').symlink_to('/never-read')
            rows=self.corpus(path);fd=V.opened_directory(path)
            try:
                with mock.patch.object(V,'fiemap_fd',return_value={'test-fixture':True}),mock.patch.object(V,'mount_id',return_value=123):
                    self.assertEqual(3,len(V.fd_census(fd,path,rows,123)))
            finally:os.close(fd)

    def test_fd_census_changed_bytes_missing_extra_hardlink_and_special_file_fail(self):
        for change in ('changed','missing','extra','hardlink','fifo'):
            with tempfile.TemporaryDirectory() as root:
                path=Path(root)/'cache';path.mkdir();(path/'data').write_text('public');rows=self.corpus(path)
                if change=='changed':(path/'data').write_text('changed')
                elif change=='missing':(path/'data').unlink()  # disposable host fixture, never actual cache
                elif change=='extra':(path/'extra').write_text('public')
                elif change=='hardlink':os.link(path/'data',path/'alias');rows=self.corpus(path)
                else:os.mkfifo(path/'fifo');rows=self.corpus(path)
                fd=V.opened_directory(path)
                try:
                    with mock.patch.object(V,'fiemap_fd',return_value={'test-fixture':True}),mock.patch.object(V,'mount_id',return_value=123),self.assertRaises(ValueError):
                        V.fd_census(fd,path,rows,123)
                finally:os.close(fd)

    def test_fd_census_file_mount_or_extent_change_fails(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'cache';path.mkdir();(path/'data').write_text('public');rows=self.corpus(path);fd=V.opened_directory(path)
            try:
                with mock.patch.object(V,'mount_id',side_effect=[123,456]),mock.patch.object(V,'fiemap_fd',return_value={'test-fixture':True}),self.assertRaises(ValueError):
                    V.fd_census(fd,path,rows,123)
                with mock.patch.object(V,'mount_id',return_value=123),mock.patch.object(V,'fiemap_fd',return_value={'changed':True}),self.assertRaises(ValueError):
                    V.fd_census(fd,path,rows,123)
            finally:os.close(fd)

    def test_removal_unapproved_target_refuses_before_mutator(self):
        with (mock.patch.object(V.os,'unlink') as unlink,mock.patch.object(V.os,'rmdir') as rmdir,
             self.assertRaises(ValueError)):
            V.remove_exact(123,'other',Path('/other'),{},io.StringIO(),[])
        unlink.assert_not_called();rmdir.assert_not_called()

    def test_live_rw_container_overlap_blocks_but_readonly_and_unrelated_mount_do_not(self):
        identity='a'*64
        for source,rw,allowed in [(str(V.SOURCE),True,False),(str(V.SOURCE.parent),True,False),
                                  (str(V.TARGETS[0].parent.parent),True,False),(str(V.SOURCE),False,True),('/tmp',True,True)]:
            info={'Id':identity,'Mounts':[{'Source':source,'RW':rw}],'State':{'Running':True}}
            with (mock.patch.object(V,'docker_read',side_effect=[(identity+'\n').encode(),json.dumps([info]).encode()]),
                 mock.patch.object(V.Path,'iterdir',return_value=[])):
                if allowed:self.assertEqual(1,len(V.no_competing_writer()))
                else:
                    with self.assertRaises(ValueError):V.no_competing_writer()

    def test_malformed_live_census_or_identity_fails_closed(self):
        for raw in (b'not-a-cid\n',('a'*64+'\n') .encode()*2):
            with mock.patch.object(V,'docker_read',return_value=raw),self.assertRaises(ValueError):V.no_competing_writer()
        with mock.patch.object(V,'docker_read',side_effect=[('a'*64+'\n').encode(),json.dumps([{'Id':'b'*64}]).encode()]),self.assertRaises(ValueError):
            V.no_competing_writer()

    def test_original_g8_oom_proves_stopped_but_not_success_and_unknown_profile_rejected(self):
        audit,summary,attempts,ref=V.authenticated_inputs()  # bounded receipts/import only; no Docker/lock/caches opened
        row,preflight,result=attempts[1];original=json.loads(row['container']['stdout'])[0]
        self.assertTrue(original['State']['OOMKilled']);self.assertNotEqual(0,original['State']['ExitCode'])
        def inspect(info):
            run=subprocess.CompletedProcess([],0,json.dumps([info]).encode(),b'')
            with mock.patch.object(audit.subprocess,'run',return_value=run):return audit.inspect_old(preflight,result)
        self.assertTrue(inspect(original)['original_profile_matches'])
        for key,value in [('Running',True),('Pid',123),('Status','running')]:
            bad=copy.deepcopy(original);bad['State'][key]=value
            with self.assertRaises(RuntimeError):inspect(bad)
        for key,value in [('Id','f'*64),('Name','/other')]:
            bad=copy.deepcopy(original);bad[key]=value
            with self.assertRaises(RuntimeError):inspect(bad)
        bad=copy.deepcopy(original);bad['HostConfig']['Memory']=48*1024**3
        with self.assertRaises(RuntimeError):inspect(bad)

    def test_protected_directory_times_may_change_but_regular_evidence_may_not(self):
        old={'path':'/p','device':1,'inode':2,'uid':1000,'gid':1000,'mode':493,'file_type':stat.S_IFDIR,'mtime_ns':1}
        new=dict(old,mtime_ns=2);V.compare_protected({'/p':old},{'/p':new})
        new=dict(old,inode=3)
        with self.assertRaises(ValueError):V.compare_protected({'/p':old},{'/p':new})
        old=dict(old,file_type=stat.S_IFREG);new=dict(old,mtime_ns=2)
        with self.assertRaises(ValueError):V.compare_protected({'/p':old},{'/p':new})

    def test_restarted_then_stopped_container_timestamps_are_not_original_custody(self):
        state={'Status':'exited','Pid':0,'Running':False,'StartedAt':'original','FinishedAt':'original'}
        audit=mock.Mock();audit.inspect_old.return_value={'state':state}
        attempts=[({'container':{'state':state}},{},{})]
        self.assertEqual(1,len(V.fresh_stop_proofs(audit,attempts)))
        audit.inspect_old.return_value={'state':dict(state,StartedAt='new-start')}
        with self.assertRaises(ValueError):V.fresh_stop_proofs(audit,attempts)

    def test_new_receipt_refuses_overwrite_and_preserves_old_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'receipt';V.write_new(p,{'phase':'intent'});before=p.read_bytes()
            with self.assertRaises(FileExistsError):V.write_new(p,{'phase':'changed'})
            self.assertEqual(before,p.read_bytes())

    def test_source_authority_error_never_acquires_lock(self):
        with (mock.patch.object(V,'authorization',return_value=({},{})),mock.patch.object(V,'authenticated_inputs',side_effect=ValueError('bad custody')),
             mock.patch.object(V.fcntl,'flock') as lock,mock.patch.object(V.os,'unlink') as unlink,
             self.assertRaises(ValueError)):V.execute(self.args())
        lock.assert_not_called();unlink.assert_not_called()

    def mocked_removal(self,path,rows,journal,removed):
        parent=V.opened_directory(path.parent)
        calls=[]
        listing_count=0
        def list_for_fd(fd):
            nonlocal listing_count
            listing_count+=1
            return ['data'] if listing_count==1 else []
        try:
            with (mock.patch.object(V,'TARGETS',(path,)),mock.patch.object(V,'mount_id',return_value=123),
                  mock.patch.object(V,'no_mounted_targets'),mock.patch.object(V.os,'listdir',side_effect=list_for_fd),
                  mock.patch.object(V.os,'unlink',side_effect=lambda name,**kw:calls.append(('unlink',name,kw))) as unlink,
                  mock.patch.object(V.os,'rmdir',side_effect=lambda name,**kw:calls.append(('rmdir',name,kw))),
                  mock.patch.object(V.os,'fsync')):
                V.remove_exact(parent,path.name,path,rows,journal,removed)
        finally:os.close(parent)
        return calls

    def test_mocked_removal_uses_only_fd_relative_admitted_leaf_then_cache_root(self):
        class Journal(io.StringIO):
            def fileno(self):return 42
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'cache';p.mkdir();(p/'data').write_text('public')
            rows={r['relative_path']:r for r in self.corpus(p)};removed=[];journal=Journal()
            calls=self.mocked_removal(p,rows,journal,removed)
            self.assertEqual([('unlink','data'),('rmdir','cache')],[(a,b) for a,b,_ in calls])
            self.assertTrue(all(set(args)=={'dir_fd'} for _,_,args in calls))
            self.assertEqual(['data','.'],[r['relative_path'] for r in removed])
            self.assertTrue((p/'data').exists())  # mutators mocked; actual disposable file untouched

    def test_journal_failure_retains_already_completed_mock_removal_in_memory(self):
        class Journal:
            def write(self,text):raise OSError('simulated journal failure')
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'cache';p.mkdir();(p/'data').write_text('public')
            rows={r['relative_path']:r for r in self.corpus(p)};removed=[]
            with self.assertRaisesRegex(OSError,'journal failure'):self.mocked_removal(p,rows,Journal(),removed)
            self.assertEqual(['data'],[r['relative_path'] for r in removed])
            self.assertTrue((p/'data').exists())

    def test_changed_file_metadata_refuses_mock_unlink(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'cache';p.mkdir();(p/'data').write_text('public');rows={r['relative_path']:r for r in self.corpus(p)}
            (p/'data').write_text('changed')
            with self.assertRaisesRegex(ValueError,'metadata changed'):self.mocked_removal(p,rows,io.StringIO(),[])
            self.assertTrue((p/'data').exists())

    def test_full_mock_lifecycle_partial_receipt_keeps_primary_and_actual_space_fields(self):
        with tempfile.TemporaryDirectory() as root:
            base=Path(root);source=base/'source';source.mkdir();output=base/'pruning'
            targets=[];attempts=[]
            for i in range(3):
                parent=base/f'work{i}';parent.mkdir();target=parent/'cache';target.mkdir();targets.append(target)
                attempts.append(({'cache_census':{'root':{'path':str(target)},'entries':[]}}, {}, {}))
            audit=mock.Mock();audit.inspect_old.return_value={'mock_stopped':True}
            def removal(parent,name,target,rows,journal,removed):
                removed.append({'target':str(target),'mock_only':True})
                raise OSError('simulated partial pruning failure')
            with (mock.patch.object(V,'TARGETS',tuple(targets)),mock.patch.object(V,'SOURCE',source),
                  mock.patch.object(V,'OUTPUT',output),mock.patch.object(V,'authorization',return_value=({},{})),
                  mock.patch.object(V,'authenticated_inputs',return_value=(audit,{},attempts,{})),
                  mock.patch.object(V,'fresh_stop_proofs',return_value=[{'mock_stopped':True}]),
                  mock.patch.object(V.fcntl,'flock') as lock,mock.patch.object(V,'protected_snapshot',return_value={}),
                  mock.patch.object(V,'no_competing_writer',return_value=[]),mock.patch.object(V,'no_mounted_targets'),
                  mock.patch.object(V,'fd_census',return_value={}),mock.patch.object(V,'remove_exact',side_effect=removal),
                  self.assertRaisesRegex(OSError,'partial pruning failure')):
                V.execute(self.args())
            receipt=json.loads((output/'pruning-receipt.json').read_text())
            self.assertEqual('failed_partial_pruning',receipt['status'])
            self.assertEqual('OSError',receipt['exception_class'])
            self.assertEqual(1,len(receipt['removed_entries']))
            self.assertIn('source_available_bytes_after',receipt)
            self.assertIn('source_available_delta_bytes',receipt)
            self.assertTrue((output/'intent.json').exists())
            self.assertTrue(all(path.exists() for path in targets))
            lock.assert_called_once()  # mocked; no source/fixture advisory lock was actually acquired

if __name__=='__main__':unittest.main(verbosity=2)
