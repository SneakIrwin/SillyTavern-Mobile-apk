package app.sillytavern.securemobile;

public final class UpdateSessionPolicyTest {
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    // Simulates preferences and ownership over recreated activity instances; no Android runtime.
    private static final class FakeOwner {
        int expected = 7;
        String token = "token-a";
        boolean active = true;
        boolean confirmationLaunched;
        int launches;
        long created = 1000;
        boolean terminal;

        void pending(int id, String supplied) {
            if (!UpdateSessionPolicy.matches(expected, token, id, supplied) || !active || confirmationLaunched) return;
            launches++;
            confirmationLaunched = true;
        }
        void finish(int id, String supplied) {
            if (!UpdateSessionPolicy.matches(expected, token, id, supplied)) return;
            terminal = true;
            expected = -1;
            token = null;
        }
        boolean blocked(long now) {
            return expected >= 0 && token != null && UpdateSessionPolicy.blocksNewSession(active, created, now);
        }
    }

    public static void main(String[] args) {
        FakeOwner owner = new FakeOwner();
        owner.pending(7, "wrong");
        check(owner.launches == 0, "forged callback launched");
        owner.pending(7, "token-a");
        owner.pending(7, "token-a"); // recreated activity replays saved intent
        check(owner.launches == 1, "pending confirmation must launch once");
        check(owner.blocked(owner.created + UpdateSessionPolicy.ORPHAN_GRACE_MS * 2), "active session must block even after grace");
        owner.finish(8, "token-a");
        check(!owner.terminal && owner.blocked(2000), "stale terminal must not clear active identity");
        owner.active = false;
        check(owner.blocked(2000), "removed session must retain a grace period for terminal callback");
        owner.finish(7, "token-a");
        check(owner.terminal && !owner.blocked(2001), "matching terminal must clear identity");
        check(UpdateSessionPolicy.blocksNewSession(false, 1000, 999), "clock rollback must not expire identity");
        check(!UpdateSessionPolicy.blocksNewSession(false, 1000, 1000 + UpdateSessionPolicy.ORPHAN_GRACE_MS), "orphan claim must eventually expire");
    }
}
