package network.tos.security.pq;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.stream.Stream;

/** Standalone ART/JNI boundary test, not an application or wallet acceptance test. */
public final class V5R2ProofNative {
    private static native byte[][] nativeVerify(byte[] anchor, byte[] request, byte[] state,
                                                long now, int[] kinds, byte[][] material);
    private static native byte[] nativeVerifyLivePersisted(String directory, boolean initialize, byte[] anchor, byte[] request, long now, int[] kinds, byte[][] material);
    public interface Transport { byte[] query(byte[] request, int maximumBytes); }
    private static native byte[] nativeAcquireLivePersisted(String directory, boolean initialize, byte[] anchor,
        byte[] request, long now, Transport transport);
    private static byte[] bytes(Path p) throws Exception { return Files.readAllBytes(p); }
    private static void check(String name, boolean ok) {
        System.out.println("PROOF_JNI_CASE " + name + " " + (ok ? "PASS" : "FAIL"));
        if (!ok) throw new AssertionError(name);
    }
    private static void refused(String name, Runnable action) {
        try { action.run(); } catch (SecurityException expected) { check(name, true); return; }
        check(name, false);
    }
    private static int kind(String name) {
        if (name.equals("masterchain-info.tl")) return 1;
        if (name.startsWith("chain-")) return 2;
        if (name.startsWith("descent-")) return 3;
        if (name.equals("config.tl")) return 4;
        if (name.equals("account.tl")) return 5;
        if (name.equals("exec-config.tl")) return 6;
        if (name.equals("libraries.tl")) return 7;
        return 0;
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("library and public fixture directory required");
        System.load(args[0]);
        Path root = java.nio.file.Paths.get(args[1]);
        byte[] anchor = bytes(root.resolve("anchor.json"));
        for (String mode : new String[]{"historical", "live"}) {
            ArrayList<Integer> tags = new ArrayList<>();
            ArrayList<byte[]> material = new ArrayList<>();
            try (Stream<Path> paths = Files.list(root.resolve(mode))) {
                for (Path path : (Iterable<Path>) paths.sorted(Comparator.comparing(Path::toString))::iterator) {
                    int tag = kind(path.getFileName().toString());
                    if (tag != 0) { tags.add(tag); material.add(bytes(path)); }
                }
            }
            int[] kinds = tags.stream().mapToInt(Integer::intValue).toArray();
            byte[][] data = material.toArray(new byte[0][]);
            byte[] request = bytes(root.resolve(mode + "-request.json"));
            byte[] state = mode.equals("live") ? bytes(root.resolve("live-state.json")) : new byte[0];
            byte[][] result = nativeVerify(anchor, request, state, 1791200932L, kinds, data);
            check(mode + "-verified", result.length == 2 && new String(result[0], java.nio.charset.StandardCharsets.UTF_8).contains("\"status\":\"verified\""));
            check(mode + "-state", mode.equals("live") ? result[1].length > 0 : result[1].length == 0);
            refused(mode + "-null-anchor", () -> nativeVerify(null, request, state, 1791200932L, kinds, data));
            refused(mode + "-missing-material", () -> nativeVerify(anchor, request, state, 1791200932L, new int[0], new byte[0][]));
            refused(mode + "-invalid-tag", () -> nativeVerify(anchor, request, state, 1791200932L, new int[]{8}, new byte[][]{{1}}));
            if (mode.equals("live")) {
                Path directory = Files.createTempDirectory(root.getParent(), "jni-checkpoint-");
                try {
                    ArrayList<Integer> firstTags = new ArrayList<>();
                    ArrayList<byte[]> firstData = new ArrayList<>();
                    for (int i = 0; i < kinds.length; i++) if (kinds[i] != 2 && kinds[i] != 3) {
                        firstTags.add(kinds[i]); firstData.add(data[i]);
                    }
                    try (Stream<Path> paths = Files.list(root.resolve("historical"))) {
                        for (Path path : (Iterable<Path>) paths.filter(p -> p.getFileName().toString().startsWith("chain-")).sorted()::iterator) {
                            firstTags.add(2); firstData.add(bytes(path));
                        }
                    }
                    int[] initialKinds = firstTags.stream().mapToInt(Integer::intValue).toArray();
                    byte[][] initialData = firstData.toArray(new byte[0][]);
                    refused("persisted-needs-enrollment", () -> nativeVerifyLivePersisted(directory.toString(), false, anchor, request, 1791200932L, initialKinds, initialData));
                    byte[] verified = nativeVerifyLivePersisted(directory.toString(), true, anchor, request, 1791200932L, initialKinds, initialData);
                    check("persisted-first-use", new String(verified, java.nio.charset.StandardCharsets.UTF_8).contains("\"status\":\"verified\""));
                    check("persisted-file-before-result", Files.isRegularFile(directory.resolve("checkpoint.json")));
                    check("persisted-reopen", nativeVerifyLivePersisted(directory.toString(), false, anchor, request, 1791200932L, kinds, data).length > 0);
                    Path acquiredDirectory = Files.createTempDirectory(root.getParent(), "jni-acquired-");
                    try {
                        byte[][] replies = {bytes(root.resolve("live/masterchain-info.tl")), bytes(root.resolve("historical/chain-0000.tl")), bytes(root.resolve("live/config.tl"))};
                        final int[] calls = {0};
                        Transport replay = (query, maximum) -> {
                            if (calls[0] >= replies.length || replies[calls[0]].length > maximum) throw new IllegalArgumentException("Public fixture query mismatch");
                            return replies[calls[0]++];
                        };
                        byte[] acquired = nativeAcquireLivePersisted(acquiredDirectory.toString(), true, anchor, request, 1791200932L, replay);
                        check("jni-acquired-live-verified", acquired.length > 0 && calls[0] == 3);
                        Path checkpoint = acquiredDirectory.resolve("checkpoint.json");
                        check("jni-acquired-committed", Files.isRegularFile(checkpoint));
                        byte[] before = bytes(checkpoint);
                        refused("jni-malformed-acquisition", () -> nativeAcquireLivePersisted(acquiredDirectory.toString(), false,
                            anchor, request, 1791200932L, (query, maximum) -> new byte[4]));
                        check("jni-malformed-preserves-state", java.util.Arrays.equals(before, bytes(checkpoint)));

                        try {
                            nativeAcquireLivePersisted(acquiredDirectory.toString(), false, anchor, request, 1791200932L,
                                (query, maximum) -> { throw new IllegalStateException("Public fixture transport failure"); });
                            check("jni-transport-exception", false);
                        } catch (IllegalStateException expected) { check("jni-transport-exception", true); }
                        check("jni-transport-preserves-state", java.util.Arrays.equals(before, bytes(checkpoint)));
                    } finally {
                        try (Stream<Path> paths = Files.walk(acquiredDirectory)) {
                            for (Path path : (Iterable<Path>) paths.sorted(Comparator.reverseOrder())::iterator) Files.delete(path);
                        }
                    }
                    Files.delete(directory.resolve("checkpoint.json"));
                    refused("persisted-loss-cannot-reset", () -> nativeVerifyLivePersisted(directory.toString(), true, anchor, request, 1791200932L, initialKinds, initialData));
                } finally {
                    try (Stream<Path> paths = Files.walk(directory)) {
                        for (Path path : (Iterable<Path>) paths.sorted(Comparator.reverseOrder())::iterator) Files.delete(path);
                    }
                }
            }
            if (mode.equals("live")) refused("live-expired", () -> nativeVerify(anchor, request, state, 1791201231L, kinds, data));
        }
    }
}
