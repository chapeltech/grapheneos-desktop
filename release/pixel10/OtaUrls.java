package app.seamlessupdate.client;

import java.io.IOException;
import java.net.URL;

/** Map GrapheneOS channel and payload names to the two fixed GitHub origins. */
final class OtaUrls {
    private OtaUrls() {}

    static URL metadata(String base, String name) throws IOException {
        if (!name.matches("frankel-[a-z][a-z0-9_-]{0,31}")) {
            throw new IOException("Invalid update channel");
        }
        return new URL(base + name);
    }

    static URL payload(String base, String target, String name) throws IOException {
        if (!target.matches("20[0-9]{8}") || !name.matches(
                "frankel(?:-streaming)?-(?:ota_update|incremental-20[0-9]{8})-" + target + "\\.zip")) {
            throw new IOException("Invalid update payload name");
        }
        return new URL(base + "frankel-0.1-" + target + "/" + name);
    }
}
