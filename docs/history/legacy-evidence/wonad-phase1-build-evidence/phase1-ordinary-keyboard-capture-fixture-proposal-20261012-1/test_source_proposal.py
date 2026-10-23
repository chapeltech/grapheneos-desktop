"""Source-only/XML host checks; NOT Kotlin/Android compile, APK, capture or endpoint proof."""
import hashlib
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

import render_patch as render

ROOT = render.ROOT
HERE = render.HERE
CANDIDATE = HERE/'candidate'
ATTR = '{http://schemas.android.com/apk/res/android}'
SOURCES = [CANDIDATE/path for path in render.ADDED if '/src/main/' in path]
ACTIVITY = CANDIDATE/(render.KOTLIN+'KeyboardCaptureActivity.kt')
API = CANDIDATE/(render.KOTLIN+'PublicKeyboardCaptureRequest.kt')
COUNTERS = CANDIDATE/(render.KOTLIN+'KeyboardCaptureCounters.kt')
WM = Path('/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7/frameworks/base/core/java/android/view/WindowManager.java')
PERMISSIONS = WM.parents[3]/'res/AndroidManifest.xml'

def normalized(node):
    return (node.tag,sorted(node.attrib.items()),(node.text or '').strip(),
            [normalized(child) for child in node])

class SourceProposalTests(unittest.TestCase):
    def test_original_manifest_and_gradle_are_bound_and_unmodified(self):
        self.assertEqual(render.MANIFEST_SHA,hashlib.sha256((ROOT/render.MANIFEST).read_bytes()).hexdigest())
        gradle=ROOT/'android/fixture/build.gradle.kts'
        self.assertEqual('58a8cabe52ccc0a29f8e194be76ef645ff47d49f663bf0411a3d5b93759d950e',
                         hashlib.sha256(gradle.read_bytes()).hexdigest())
        text=gradle.read_text()
        self.assertIn('applicationId = "org.wonad.fixture"',text)
        self.assertIn('compileSdk = 35',text);self.assertIn('targetSdk = 35',text)
        self.assertNotIn('signingConfig',text)

    def test_manifest_has_only_normal_capture_permission_and_three_new_activities(self):
        before=ET.fromstring((ROOT/render.MANIFEST).read_bytes())
        after=ET.fromstring((CANDIDATE/render.MANIFEST).read_bytes())
        permission=[p for p in after.findall('uses-permission')
                    if p.get(ATTR+'name')=='android.permission.CAPTURE_KEYBOARD']
        self.assertEqual(1,len(permission));self.assertEqual(1,len(permission[0].attrib))
        after.remove(permission[0])
        app=after.find('application');old_names={p.get(ATTR+'name') for p in before.findall('./application/activity')}
        new=[p for p in app.findall('activity') if p.get(ATTR+'name') not in old_names]
        self.assertEqual(3,len(new))
        for child in new:app.remove(child)
        self.assertEqual(normalized(before),normalized(after))

    def test_three_public_document_tasks_have_distinct_affinities_and_visible_launchers(self):
        manifest=ET.fromstring((CANDIDATE/render.MANIFEST).read_bytes())
        rows=[p for p in manifest.findall('./application/activity') if 'KeyboardCapture' in p.get(ATTR+'name','')]
        self.assertEqual({'.KeyboardCaptureOneActivity','.KeyboardCaptureTwoActivity','.KeyboardCapturePhoneActivity'},
                         {p.get(ATTR+'name') for p in rows})
        self.assertEqual(3,len({p.get(ATTR+'taskAffinity') for p in rows}))
        for row in rows:
            for name,value in (('exported','true'),('launchMode','standard'),('documentLaunchMode','always'),
                               ('resizeableActivity','true'),('excludeFromRecents','false')):
                self.assertEqual(value,row.get(ATTR+name))
            self.assertEqual(['android.intent.category.LAUNCHER'],
                             [p.get(ATTR+'name') for p in row.findall('./intent-filter/category')])
        self.assertEqual(16,len(manifest.findall('./application/activity')))

    def test_manifest_never_adds_platform_shared_uid_or_privileged_permission(self):
        text=(CANDIDATE/render.MANIFEST).read_text()
        for forbidden in ('sharedUserId','BIND_', 'MANAGE_', 'INJECT_EVENTS','SYSTEM_ALERT_WINDOW','platform'):
            self.assertNotIn(forbidden,text)
        self.assertEqual('f160379bc267453814f0d9359a01a59897715790f7977fb8a2107d5d194ba54f',
                         hashlib.sha256(PERMISSIONS.read_bytes()).hexdigest())
        permission=ET.parse(PERMISSIONS).getroot()
        rows=[row for row in permission.findall('permission') if row.get(ATTR+'name')=='android.permission.CAPTURE_KEYBOARD']
        self.assertEqual(1,len(rows));self.assertEqual('normal',rows[0].get(ATTR+'protectionLevel'))
        self.assertEqual('com.android.hardware.input.request_key_capture_api',rows[0].get(ATTR+'featureFlag'))

    def test_primary_source_public_method_names_signatures_and_permission_match(self):
        self.assertEqual('acb92d789151e0f0907b44223c7f23c3cbc0332e1687f93ddabc52003a7e85eb',hashlib.sha256(WM.read_bytes()).hexdigest())
        text=WM.read_text();api=API.read_text()
        self.assertIn('public void setKeyboardCaptureEnabled(boolean enabled)',text)
        self.assertIn('public boolean hasKeyboardCapture()',text)
        self.assertIn('@RequiresPermission(permission.CAPTURE_KEYBOARD)',text)
        self.assertIn('getMethod("setKeyboardCaptureEnabled", java.lang.Boolean.TYPE)',api)
        self.assertIn('getMethod("hasKeyboardCapture")',api)
        for forbidden in ('setAccessible','getDeclaredMethod','getDeclaredField','inputFeatures','INPUT_FEATURE_'):
            self.assertNotIn(forbidden,api)

    def test_ordinary_activity_uses_public_params_and_defaults_off_with_visible_controls(self):
        text=ACTIVITY.read_text()
        self.assertIn(': Activity()',text);self.assertNotIn(': FixtureActivity()',text)
        self.assertIn('PublicKeyboardCaptureRequest(WindowManager.LayoutParams::class.java)',text)
        self.assertIn('requestCapture(false)',text)
        for label in ('Enable keyboard capture','Disable keyboard capture','Reset key counters'):
            self.assertIn(label,text)
        for forbidden in ('getIntent()', 'getBooleanExtra','getStringExtra','Settings.', 'grantRuntimePermission',
                          'requestPermissions','setFocusedTask','ProcessBuilder','Runtime.getRuntime','System.load'):
            self.assertNotIn(forbidden,text)

    def test_no_typed_content_or_individual_keycodes_retained(self):
        for path in SOURCES:
            text=path.read_text()
            for forbidden in ('getText(','.unicodeChar','.characters','getUnicodeChar','getCharacters',
                              'last_key','KeyCharacterMap','EditText','TextWatcher','Clipboard','Log.',
                              'writeText','writeBytes','SharedPreferences','.message'):
                self.assertNotIn(forbidden,text,path.name)
        self.assertEqual(1,ACTIVITY.read_text().count('event.keyCode'))
        self.assertIn('event.keyCode == KeyEvent.KEYCODE_ESCAPE',ACTIVITY.read_text())
        self.assertNotIn('keyCode',COUNTERS.read_text())
        self.assertNotIn('ArrayDeque',COUNTERS.read_text())

    def test_counters_are_fixed_saturating_aggregate_fields_with_explicit_reset(self):
        text=COUNTERS.read_text()
        self.assertIn('const val LIMIT = 1_000_000',text)
        self.assertIn('if (value < limit) return value + 1',text)
        self.assertIn('saturated = true',text);self.assertIn('return limit',text)
        self.assertIn('@Synchronized fun observe',text)
        self.assertIn('@Synchronized fun snapshot',text)
        self.assertIn('@Synchronized fun clear',text)
        self.assertIn('require(repeat >= 0)',text)

    def test_errors_unavailable_permission_and_attribute_mismatch_cannot_claim_capture(self):
        text=API.read_text();activity=ACTIVITY.read_text()
        for status in ('API_UNAVAILABLE','NORMAL_PERMISSION_MISSING','PUBLIC_API_ERROR',
                       'WINDOW_UPDATE_ERROR','ATTRIBUTE_MISMATCH','ATTRIBUTES_APPLIED'):
            self.assertIn(status,text)
        self.assertLess(text.index('if (enabled && !permissionGranted)'),text.index('setter.invoke(params, enabled)'))
        self.assertIn('cause.javaClass.name.take(128)',text)
        self.assertIn('cause is VirtualMachineError || cause is ThreadDeath',text)
        self.assertIn('.put("actual_system_capture_proven", false)',activity)
        self.assertIn('.put("attribute_enabled", result.attributeEnabled ?: JSONObject.NULL)',activity)

    def test_dump_is_bounded_cached_aggregate_identity_not_hidden_input_token(self):
        text=ACTIVITY.read_text()
        self.assertIn('@Volatile private var observation = "{}"',text)
        self.assertIn('WONAD_KEYBOARD_CAPTURE',text)
        for name in ('component','instance','task','display','uid','pid','focused','top_resumed',
                     'capture_requested','permission_granted','public_api_status','down_count','up_count',
                     'escape_down_count','escape_up_count','counter_limit','counters_saturated'):
            self.assertIn('.put("'+name+'"',text)
        self.assertIn('public_window_token_local_identity',text)
        self.assertNotIn('input_token',text)

    def test_all_thirteen_future_jvm_cases_are_source_declared_not_claimed_executed(self):
        found=[]
        for path in render.ADDED:
            if '/src/test/' not in path:continue
            text=(CANDIDATE/path).read_text()
            found.extend(re.findall(r'@Test\s+fun (\w+)\(',text))
        self.assertEqual(13,len(found));self.assertEqual(13,len(set(found)))

    def test_candidate_manifest_matches_renderer_and_patch_has_only_six_targets(self):
        self.assertEqual(render.manifest_bytes(),(CANDIDATE/render.MANIFEST).read_bytes())
        patch=render.patch()
        targets=re.findall(r'^\+\+\+ b/(.+)$',patch,re.MULTILINE)
        self.assertEqual([render.MANIFEST,*render.ADDED],targets)
        self.assertNotIn('build.gradle',patch)

if __name__=='__main__':
    unittest.main(verbosity=2)
