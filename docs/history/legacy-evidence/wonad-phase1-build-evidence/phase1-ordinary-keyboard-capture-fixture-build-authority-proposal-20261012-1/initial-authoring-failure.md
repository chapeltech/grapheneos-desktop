First stdout-only proposal replay (tool chunk 62e0fb) exited1 at manifest_inventory:

    ValueError: Ordinary fixture manifest package/UID shape changed

The draft incorrectly expected a source manifest package attribute. Current source manifest has no package attribute; exact pinned Gradle namespace/applicationId supplies org.wonad.fixture. No Docker/tool inventory/Gradle/build/sign/guest code exists or ran. This is an external proposal authoring error, not a product failure or runtime RED. Initial source bytes are retained separately before the correction.
