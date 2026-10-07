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
            if (mode.equals("live")) refused("live-expired", () -> nativeVerify(anchor, request, state, 1791201231L, kinds, data));
        }
    }
}
