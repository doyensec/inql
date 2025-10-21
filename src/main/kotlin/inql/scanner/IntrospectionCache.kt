package inql.scanner

import inql.InQL
import inql.Logger

/*
    This class is just a convenience class to keep track of the introspection schemas
    retrieved from InQL Scanner so that it's possible to reuse it without requesting
    the schema and analyzing it again.

    Effectively it's just a wrapper around a HashMaps.
    The structure is something like: Cache[URL][Profile?] = Parsed GraphQL Schema
 */
class IntrospectionCache(val inql: InQL) {
    companion object {
        const val NO_PROFILE = "NO_PROFILE"
    }

    private val cache = HashMap<String, HashMap<String, ScanResult>>()

    fun get(url: String, profile: String = NO_PROFILE): ScanResult? {
        return this.cache[url]?.get(profile)
    }

    fun put(url: String, profile: String = NO_PROFILE, scanResult: ScanResult) {
        if (!this.cache.containsKey(url)) {
            this.cache[url] = HashMap<String, ScanResult>()
        }

        this.cache[url]!![profile] = scanResult
    }

    fun putIfNewer(url: String, profile: String = NO_PROFILE, scanResult: ScanResult) {
        val existingTS = this.get(url, profile)?.ts
        if (existingTS == null || existingTS.isBefore(scanResult.ts)) {
            this.put(url, profile, scanResult)
        }
    }

    fun getSchemasForUrl(url: String): Collection<String> {
        return this.cache[url]?.keys ?: emptySet()
    }

    fun remove(url: String, profile: String = NO_PROFILE) {
        this.cache[url]?.remove(profile)
    }

    fun populateFromScanner() {
        Logger.debug("Populating from open Scanner Tabs...")
        val tabs = this.inql.scanner.getScannerTabs()
        for (tab in tabs) {
            Logger.debug("Found tab for url ${tab.url}")
            if (tab.scanResults.isNotEmpty()) {
                Logger.debug("Found result for ${tab.url}, inserting...")
                this.putIfNewer(tab.url, tab.linkedProfile?.name ?: NO_PROFILE, tab.scanResults.last())
            }
        }
        Logger.debug("All cached urls: ${this.cache.keys}")

    }

    fun refresh() {
        this.cache.clear()
        this.populateFromScanner()
    }
}