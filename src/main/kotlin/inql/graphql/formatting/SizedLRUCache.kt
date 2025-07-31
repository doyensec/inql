package inql.graphql.formatting

import java.util.LinkedHashMap

/**
 * A memory-aware Least Recently Used (LRU) cache that limits its contents
 * based on an estimated total memory footprint rather than number of entries.
 *
 * Entries are automatically evicted in LRU order when the estimated total
 * size exceeds [maxBytes]. The size of each entry is calculated via the
 * [estimateEntrySize] function provided at construction time.
 *
 * @param maxBytes Initial maximum estimated memory usage (in bytes)
 * @param estimateEntrySize A lambda that returns the estimated memory size (in bytes)
 *                          of a cache entry, given its key and value.
 */
class SizedLRUCache<K, V>(
    maxBytes: Long,
    private val estimateEntrySize: (K, V) -> Long
) : LinkedHashMap<K, V>(16, 0.75f, false) {

    var maxBytes: Long = maxBytes
        set(value) {
            field = value
            evictIfNeeded()
        }

    private var currentSize = 0L

    /**
     * Inserts a key-value pair into the cache. If the key already exists,
     * its size is updated accordingly. Automatically evicts oldest entries
     * if the new size exceeds the configured [maxBytes] limit.
     */
    override fun put(key: K, value: V): V? {
        val oldValue = super.put(key, value)
        currentSize += estimateEntrySize(key, value)
        if (oldValue != null) {
            currentSize -= estimateEntrySize(key, oldValue)
        }
        evictIfNeeded()
        return oldValue
    }

    /**
     * Removes a key-value pair from the cache and updates the internal
     * size counter accordingly.
     */
    override fun remove(key: K): V? {
        val removed = super.remove(key)
        if (removed != null) {
            currentSize -= estimateEntrySize(key, removed)
        }
        return removed
    }

    /**
     * Returns the current estimated size of the cache in bytes.
     */
    fun currentCacheSize(): Long = currentSize

    private fun evictIfNeeded() {
        val iterator = entries.iterator()
        while (currentSize > maxBytes && iterator.hasNext()) {
            val entry = iterator.next()
            currentSize -= estimateEntrySize(entry.key, entry.value)
            iterator.remove()
        }
    }
}
