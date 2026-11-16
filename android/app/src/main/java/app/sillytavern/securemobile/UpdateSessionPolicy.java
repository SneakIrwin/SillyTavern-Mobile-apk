package app.sillytavern.securemobile;

/** Small, Android-independent decisions used by the update-session owner. */
final class UpdateSessionPolicy {
    static final long ORPHAN_GRACE_MS = 5 * 60 * 1000L;

    static boolean matches(int expectedId, String expectedToken, int actualId, String actualToken) {
        return actualId >= 0 && actualId == expectedId && expectedToken != null
                && expectedToken.equals(actualToken);
    }

    static boolean blocksNewSession(boolean owned, long missingSince, long now) {
        return owned || missingSince <= 0 || now < missingSince || now - missingSince < ORPHAN_GRACE_MS;
    }

    private UpdateSessionPolicy() { }
}
