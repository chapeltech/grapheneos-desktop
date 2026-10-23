#!/usr/bin/env python3
"""Print the source-only ordinary fixture patch. Never write/stage/build/install."""
import difflib
import hashlib
from pathlib import Path
import sys

ROOT = Path('/u/elric/tree/wonad')
HERE = Path(__file__).resolve().parent
MANIFEST = 'android/fixture/src/main/AndroidManifest.xml'
MANIFEST_SHA = 'f65373bc8325c0539cdf6e177d193e0df4b9a52d5689bd8bc90c0b2bbadcf3a8'
KOTLIN = 'android/fixture/src/main/kotlin/org/wonad/fixture/'
TESTS = 'android/fixture/src/test/kotlin/org/wonad/fixture/'
ADDED = (KOTLIN+'KeyboardCaptureCounters.kt', KOTLIN+'PublicKeyboardCaptureRequest.kt',
         KOTLIN+'KeyboardCaptureActivity.kt', TESTS+'KeyboardCaptureCountersTest.kt',
         TESTS+'PublicKeyboardCaptureRequestTest.kt')

ACTIVITIES = '''        <activity android:name=".KeyboardCaptureOneActivity" android:exported="true"
            android:label="Wonad keyboard capture one" android:taskAffinity="org.wonad.fixture.keyboard.capture.one"
            android:launchMode="standard" android:documentLaunchMode="always" android:excludeFromRecents="false"
            android:resizeableActivity="true" android:configChanges="screenSize|smallestScreenSize|orientation|screenLayout|density">
            <intent-filter><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent-filter>
        </activity>
        <activity android:name=".KeyboardCaptureTwoActivity" android:exported="true"
            android:label="Wonad keyboard capture two" android:taskAffinity="org.wonad.fixture.keyboard.capture.two"
            android:launchMode="standard" android:documentLaunchMode="always" android:excludeFromRecents="false"
            android:resizeableActivity="true" android:configChanges="screenSize|smallestScreenSize|orientation|screenLayout|density">
            <intent-filter><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent-filter>
        </activity>
        <activity android:name=".KeyboardCapturePhoneActivity" android:exported="true"
            android:label="Wonad keyboard capture phone" android:taskAffinity="org.wonad.fixture.keyboard.capture.phone"
            android:launchMode="standard" android:documentLaunchMode="always" android:excludeFromRecents="false"
            android:resizeableActivity="true" android:configChanges="screenSize|smallestScreenSize|orientation|screenLayout|density">
            <intent-filter><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent-filter>
        </activity>
'''

def manifest_bytes():
    source=(ROOT/MANIFEST).read_bytes()
    if hashlib.sha256(source).hexdigest()!=MANIFEST_SHA:
        raise ValueError('Current original fixture manifest changed; review new source')
    text=source.decode('utf-8')
    permission='    <uses-permission android:name="android.permission.CAMERA" />\n'
    end='    </application>\n'
    if text.count(permission)!=1 or text.count(end)!=1:
        raise ValueError('Manifest source anchors changed')
    text=text.replace(permission,permission+'    <uses-permission android:name="android.permission.CAPTURE_KEYBOARD" />\n')
    return text.replace(end,ACTIVITIES+end).encode('utf-8')

def patch():
    result=[]
    for relative in (MANIFEST,*ADDED):
        before=(ROOT/relative).read_text() if relative==MANIFEST else ''
        if relative!=MANIFEST and (ROOT/relative).exists():
            raise ValueError('New source target already exists: '+relative)
        after=(HERE/'candidate'/relative).read_text()
        result.append(''.join(difflib.unified_diff(before.splitlines(keepends=True),after.splitlines(keepends=True),
            fromfile='a/'+relative if before else '/dev/null',tofile='b/'+relative)))
    return ''.join(result)

if __name__=='__main__':
    if sys.argv[1:]==['--manifest']:
        sys.stdout.buffer.write(manifest_bytes())
    elif not sys.argv[1:]:
        sys.stdout.write(patch())
    else:
        raise ValueError('Only stdout --manifest or source patch rendering is supported')
