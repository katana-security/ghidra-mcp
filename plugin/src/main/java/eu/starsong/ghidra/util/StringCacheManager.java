package eu.starsong.ghidra.util;

import eu.starsong.ghidra.model.StringInfo;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe in-memory cache for string data in a Ghidra program.
 *
 * Uses double-checked locking: fast path without lock if cache is valid,
 * slow path with synchronized build if cache needs rebuilding.
 * Only one thread builds the cache; others wait and reuse the result.
 *
 * Auto-invalidates when the program changes (via modificationNumber) or
 * when a different Program instance is loaded.
 */
public class StringCacheManager {

    private static final class CacheEntry {
        final List<StringInfo> strings;
        final long modificationNumber;
        final Program program;
        final long buildTimeMs;

        CacheEntry(List<StringInfo> strings, long modificationNumber, Program program, long buildTimeMs) {
            this.strings = strings;
            this.modificationNumber = modificationNumber;
            this.program = program;
            this.buildTimeMs = buildTimeMs;
        }
    }

    private final AtomicReference<CacheEntry> cacheRef = new AtomicReference<>(null);
    private final Object buildLock = new Object();

    /**
     * Get the cached string list, building it synchronously if needed.
     * Thread-safe: only one thread builds at a time, others wait.
     */
    public List<StringInfo> getOrBuild(Program program) {
        // Fast path: cache exists and is valid
        CacheEntry current = cacheRef.get();
        if (isValidFor(current, program)) {
            return current.strings;
        }

        // Slow path: need to build or wait for build
        synchronized (buildLock) {
            // Double-check after acquiring lock
            current = cacheRef.get();
            if (isValidFor(current, program)) {
                return current.strings;
            }

            // Build the cache
            return buildCacheSync(program);
        }
    }

    /**
     * Explicitly invalidate the cache. Next getOrBuild() call will rebuild.
     */
    public void invalidate() {
        cacheRef.set(null);
    }

    /**
     * Get cache status info for the debug endpoint.
     */
    public CacheStatus getStatus(Program program) {
        CacheEntry current = cacheRef.get();
        if (current == null) {
            return new CacheStatus(false, 0, 0, false, 0);
        }
        boolean valid = isValidFor(current, program);
        return new CacheStatus(true, current.strings.size(), current.buildTimeMs, valid, current.modificationNumber);
    }

    private boolean isValidFor(CacheEntry entry, Program program) {
        if (entry == null || program == null) {
            return false;
        }
        // Check both program identity and modification number
        return entry.program == program
            && entry.modificationNumber == program.getModificationNumber();
    }

    private List<StringInfo> buildCacheSync(Program program) {
        long startTime = System.currentTimeMillis();
        Msg.info(this, "StringCacheManager: building string cache for " + program.getName() + "...");

        List<StringInfo> list = new ArrayList<>();

        for (Data data : DefinedDataIterator.byDataType(program,
                dt -> dt instanceof AbstractStringDataType)) {
            String address = data.getAddress().toString();
            String value = data.getDefaultValueRepresentation();
            int length = data.getLength();
            String typeName = data.getDataType().getName();

            Symbol symbol = program.getSymbolTable().getPrimarySymbol(data.getAddress());
            String symbolName = (symbol != null) ? symbol.getName() : "";

            list.add(new StringInfo(address, value, length, typeName, symbolName));
        }

        List<StringInfo> immutableList = Collections.unmodifiableList(list);
        long buildTimeMs = System.currentTimeMillis() - startTime;

        CacheEntry entry = new CacheEntry(immutableList, program.getModificationNumber(), program, buildTimeMs);
        cacheRef.set(entry);

        Msg.info(this, "StringCacheManager: cached " + immutableList.size() + " strings in " + buildTimeMs + "ms");
        return immutableList;
    }

    /**
     * Simple status record for the cache debug endpoint.
     */
    public static final class CacheStatus {
        public final boolean cached;
        public final int size;
        public final long buildTimeMs;
        public final boolean valid;
        public final long modificationNumber;

        public CacheStatus(boolean cached, int size, long buildTimeMs, boolean valid, long modificationNumber) {
            this.cached = cached;
            this.size = size;
            this.buildTimeMs = buildTimeMs;
            this.valid = valid;
            this.modificationNumber = modificationNumber;
        }
    }
}
