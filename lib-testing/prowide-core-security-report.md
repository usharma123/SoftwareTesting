# Security Scan — pw-swift-core (prowide/prowide-core) — 2026-05-29

## Summary

| Item | Detail |
|---|---|
| **Scope** | `github.com/prowide/prowide-core` · commit `2d2baee7` (main, SRU2025) · Mode: audit |
| **Tools run** | semgrep, gitleaks (dir + history), trufflehog (verified), trivy fs, trivy config, syft, grype |
| **Not installed / coverage gaps** | SpotBugs/FindSecBugs (Java 11 toolchain required; only Java 25 present — install JDK 11 to run); osv-scanner (no Gradle lockfile — generate with `./gradlew dependencies --write-locks`); Gradle build failed — transitive deps not resolved |
| **SARIF outputs** | `/tmp/scan-results/prowide-core/` |
| **SBOM** | `/tmp/scan-results/prowide-core/sbom.cdx.json` (CI/workflow deps only — Java runtime deps need lockfile) |
| **Findings** | Crit 0 · High 1 · Med 3 · Low 3 · Info 4 |
| **Secrets** | None — gitleaks scanned 716 commits, 26 MB; TruffleHog: 0 verified credentials |
| **Dependency CVEs** | 0 — commons-lang3 3.20.0, commons-text 1.15.0, gson 2.14.0 all clean |

---

## Findings

### [HIGH] Conditional XXE Protection Bypass via Classpath Property Override

- **Severity rationale**: Not a direct XXE — but every XXE mitigation in the library can be silently disabled by a single classpath file, turning a defended parser into an undefended one. SWIFT messages contain XML; a successful bypass enables file-read SSRF from the parsing server.
- **Standards**: OWASP A05:2021 (Security Misconfiguration) · CWE-693 (Protection Mechanism Failure) · CWE-611 (XML External Entity)
- **Location**: `src/main/java/com/prowidesoftware/swift/utils/SafeXmlUtils.java:79–234` and `src/main/java/com/prowidesoftware/swift/utils/PropertyLoader.java:60–68`

**Evidence**:

`SafeXmlUtils` is the library's central "safe XML" gateway — every parser and transformer the library creates goes through it. Each protective feature is gated by:

```java
// PropertyLoader.java:60-68
static String[] getPropertyArray(String key) {
    ...
    return propertyValue.split(",");   // reads pw-swift-core.properties
}

// SafeXmlUtils.java:300-303
private static boolean applyFeature(final String feature) {
    final String[] prop = PropertyLoader.getPropertyArray(FEATURE_IGNORE_PROPERTY);
    return (!ArrayUtils.contains(prop, feature));
}
```

`FEATURE_IGNORE_PROPERTY = "safeXmlUtils.ignore"`. Any feature listed in `pw-swift-core.properties` under that key will return `false` from `applyFeature()`, skipping that protection entirely. Creating the file:

```
safeXmlUtils.ignore=http://apache.org/xml/features/disallow-doctype-decl,http://xml.org/sax/features/external-general-entities,http://javax.xml.XMLConstants/feature/secure-processing
```

…and placing it anywhere on the deploying application's classpath silently re-enables XXE in the `DocumentBuilderFactory`, `SAXParserFactory`, and `TransformerFactory`.

The documented rationale is compatibility with old Xerces versions. The problem is that the bypass is **classpath-wide**, not scoped to a specific parser call — any tenant sharing the classloader (in an app-server deployment) can suppress protections for all others.

- **Impact**: Attacker who can plant or influence classpath resources in a deployed application can trigger XXE: read local files (`/etc/passwd`, private keys), pivot to internal SSRF, or crash the parser.
- **Remediation**: Remove the `applyFeature()` bypass entirely, or scope it to a per-call opt-in rather than a global classpath suppression. If compatibility exceptions must be supported, throw a loud exception rather than silently degrading security. Document clearly in release notes that `safeXmlUtils.ignore` disables security controls.

---

### [MEDIUM] Dead SAXParser Post-Creation Feature Calls

- **Severity rationale**: The `reader` object returned from `SafeXmlUtils.reader()` is missing the secondary XXE mitigations that were intended to be set on it. They are set on the already-used factory instead, making those lines no-ops.
- **Standards**: OWASP A05:2021 · CWE-693 · CWE-611
- **Location**: `src/main/java/com/prowidesoftware/swift/utils/SafeXmlUtils.java:162–188`

**Evidence**:

```java
SAXParser saxParser = spf.newSAXParser();       // line 162 — parser created
XMLReader reader = saxParser.getXMLReader();    // line 163 — reader obtained

// Lines 167-181: features set on `spf` (the factory) — NOT on `reader`
feature = "http://apache.org/xml/features/disallow-doctype-decl";
if (applyFeature(feature)) {
    spf.setFeature(feature, true);              // ← no effect: parser already created
}
feature = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
if (applyFeature(feature)) {
    spf.setFeature(feature, false);             // ← no effect
}
feature = "http://xml.org/sax/features/external-general-entities";
if (applyFeature(feature)) {
    spf.setFeature(feature, false);             // ← no effect
}
feature = "http://xml.org/sax/features/external-parameter-entities";
if (applyFeature(feature)) {
    spf.setFeature(feature, false);             // ← no effect
}
return reader;
```

Post-creation `spf.setFeature()` calls have no effect on the already-created reader. The primary protection (`disallow-doctype-decl` set before `newSAXParser()` at line 151–153) does fire — so the reader is partially hardened — but the secondary belt-and-suspenders protections (external-general-entities, external-parameter-entities, load-external-dtd) are silently skipped.

- **Impact**: The `XMLReader` returned by `SafeXmlUtils.reader()` lacks the secondary XXE mitigations. Depending on the XML processor and JDK, this may allow entity expansion through parameters/external entities even if DOCTYPE is technically forbidden.
- **Remediation**: Move lines 167–181 to set features on `reader` (via `reader.setFeature()`) instead of `spf`.

---

### [MEDIUM] Unvalidated Input to `Class.forName` in `Field.getField()`

- **Severity rationale**: The `name` parameter passed to `Class.forName()` is taken directly from SWIFT message content without validation. The safe `fromJson()` overload in the same class validates against `^\d{2,3}[A-Z]?$` before calling `Class.forName()` — the inconsistency is the defect.
- **Standards**: OWASP A03:2021 (Injection) · CWE-470 (Externally-Controlled Input to Select Classes)
- **Location**: `src/main/java/com/prowidesoftware/swift/model/field/Field.java:200–218`

**Evidence**:

```java
// Field.getField() — NO validation:
public static Field getField(final String name, final String value) {
    final Class<?> c = Class.forName(
        "com.prowidesoftware.swift.model.field.Field" + name);   // ← raw `name`
    ...
}

// Field.fromJson() — validated path (same file, line 409):
if (!name.matches(fieldNamePattern)) {   // "^\d{2,3}[A-Z]?$"
    return null;
}
final Class<?> c = Class.forName(
    "com.prowidesoftware.swift.model.field.Field" + name);       // ← safe after guard
```

A crafted SWIFT field name containing `.` characters (e.g., `"20.some.Class"`) would produce `Class.forName("com.prowidesoftware.swift.model.field.Field20.some.Class")`. While no matching class likely exists in the prowide package, `Class.forName()` on JVM implementations will search the full classpath. Static initializers of any matched class would execute. The exception-on-failure path (lines 210–216) swallows errors silently.

- **Impact**: Forced classpath scan with attacker-influenced class names; potential execution of static initializers in unexpected classes; information disclosure via timing differences between "class found" and "class not found" paths.
- **Remediation**: Apply the same `fieldNamePattern` validation used in `fromJson()` to `getField()` before calling `Class.forName()`. One line fix: add `if (!name.matches(fieldNamePattern)) return null;` at the top of `getField()`.

---

### [MEDIUM] Public API to Modify JVM Process Environment at Runtime

- **Severity rationale**: A production library shipping a publicly-callable method that reflectively mutates `java.lang.ProcessEnvironment` — including a `map.clear()` that can wipe all process env vars — is an unusual and dangerous capability, especially given that the same library parses untrusted financial messages.
- **Standards**: CWE-269 (Improper Privilege Management) · CWE-470
- **Location**: `src/main/java/com/prowidesoftware/deprecation/DeprecationUtils.java:113–170`

**Evidence**:

```java
// Public API — callable by any code in the JVM:
public static void setEnv(EnvironmentVariableKey... keys) { ... }
public static void clearEnv() { setEnv(PW_DEPRECATED, ""); }

// Private impl — uses deep reflection on JVM internals:
private static void setEnv(final String key, final String value) {
    Class<?> processEnvironmentClass = Class.forName("java.lang.ProcessEnvironment");
    Field theEnvironmentField = processEnvironmentClass.getDeclaredField("theEnvironment");
    theEnvironmentField.setAccessible(true);                  // bypasses Java access control
    Map<String, String> env = (Map) theEnvironmentField.get(null);
    env.put(key, value);
    ...
    // fallback path:
    map.clear();               // ← CLEARS ALL environment variables
    map.put(key, value);
}
```

`build.gradle:329` exposes the intent: `jvmArgs '--add-opens=java.base/java.lang=ALL-UNNAMED'` is required in tests to allow this code to run without illegal-access warnings on modern JDKs. The method is in production library code, not a test utility. The fallback `map.clear()` is especially dangerous — an accidental call to `clearEnv()` would erase `PATH`, `HOME`, `JAVA_HOME`, and all other environment variables from the process.

- **Impact**: If an attacker achieves any code execution context where they can call this method (e.g., via a deserialization gadget chain or other RCE), they can modify or erase environment variables. Environment variable modification can be used to subvert subsequent calls to subprocesses, affect security-sensitive config loaded from env, or cause DoS.
- **Remediation**: Move `setEnv()` and `clearEnv()` to a test-only utility class not included in the production JAR. The deprecation mechanism should rely on JVM system properties or a thread-local instead of process environment.

---

### [LOW] Unsafe Reflection on Message Type in `SwiftMessage.toMT()`

- **Severity rationale**: The SWIFT message type from block 2 is user-controlled and used directly in `Class.forName()`. The fixed package prefix severely limits exploitation. Flagged because the same pattern is a known Java gadget-chain primitive.
- **Standards**: CWE-470 · OWASP A03:2021
- **Location**: `src/main/java/com/prowidesoftware/swift/model/SwiftMessage.java:1563–1593`

**Evidence**:

```java
className.append("com.prowidesoftware.swift.model.mt.mt");
className.append(type.charAt(0));    // first char of type from block 2
className.append("xx.MT");
className.append(type);              // full type from block 2 — no explicit validation
Class.forName(className.toString())
```

For a normal MT message type like `"103"`, this resolves to `com.prowidesoftware.swift.model.mt.mt1xx.MT103` — correct. If `type` is crafted (e.g., a malformed FIN message provides `"103.evil.Class"`), the resulting class name would be `com.prowidesoftware.swift.model.mt.mt1xx.MT103.evil.Class` — which does not exist and causes `ClassNotFoundException` (silently swallowed). Exploitation is not realistic, but the pattern is architecturally sloppy.

- **Remediation**: Validate `type` with `type.matches("\\d{3}")` before use in `className`.

---

### [LOW] GitHub Actions: Unpinned Mutable Tag References

- **Standards**: OWASP A08:2021 (Software and Data Integrity Failures) · CWE-494
- **Location**: `.github/workflows/codeql.yml`, `.github/workflows/gradle.yml`

**Evidence**:

- `codeql.yml`: uses `actions/checkout@v3` (outdated — v4 current), `github/codeql-action/init@v2`, `autobuild@v2`, `analyze@v2` (all outdated — v3 current)
- `gradle.yml`: uses `actions/checkout@v4`, `actions/setup-java@v4`, `gradle/actions/setup-gradle@v4`, `gradle/actions/dependency-submission@v4`

All are pinned to mutable semver tags. Tags can be force-pushed. A compromised `actions` or `gradle` org account could redirect these to malicious code that exfiltrates secrets or injects build artifacts.

- **Remediation**: Pin to immutable commit SHA. Example: `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`

---

### [LOW] Third-Party Analytics Script Injected into Generated Javadoc

- **Standards**: OWASP A08:2021 · CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Location**: `build.gradle:124–125`

**Evidence**:

```groovy
options.bottom = '<script src="//static.getclicky.com/js"></script>' +
                 '<script>try{ clicky.init(101039278); }catch(e){}</script>'
options.addBooleanOption("-allow-script-in-comments", true)
```

Every page of the generated Javadoc loads a JavaScript file from `//static.getclicky.com` (protocol-relative — degrades to `http://` on non-HTTPS origins, enabling MitM). If the Clicky CDN is compromised, arbitrary JavaScript executes in all Javadoc browsers. The tracking ID `101039278` is hardcoded, identifying the Prowide account. `allow-script-in-comments` further expands the JS execution surface.

- **Impact**: XSS via compromised CDN; user tracking without consent; degraded integrity of published Javadoc.
- **Remediation**: Remove the tracking script from generated docs. If analytics are needed, use a privacy-respecting self-hosted solution or configure it outside the published artifact.

---

### [INFO] 22 Serializable Model Classes Without `readObject()` Guards

- **Location**: `src/main/java/com/prowidesoftware/swift/model/` (SwiftMessage, SwiftBlock, Tag, SwiftTagListBlock, UnparsedTextList, etc.)
- **Risk context**: The library's core model objects implement `Serializable` without custom `readObject()` methods. This is a gadget-chain risk only if the **consuming application** accepts untrusted serialized streams of these objects. The library itself does not. Noted for library consumers who serialize/deserialize `SwiftMessage` objects over untrusted channels.

---

### [INFO] MD5 Used for Duplicate Detection

- **Location**: `src/main/java/com/prowidesoftware/swift/model/SwiftMessageUtils.java:451`
- **Standards**: CWE-327
- Javadoc explicitly states this is not for security. No CVSS score warranted. Note for consumers who might misuse the `md5()` utility for security purposes.

---

### [INFO] No Gradle Dependency Lockfile

- The project has no `gradle.lockfile`. Without one, transitive dependency resolution is non-deterministic across builds. A compromised upstream package could be pulled in during a rebuild.
- **Remediation**: Run `./gradlew dependencies --write-locks` and commit the generated `gradle.lockfile`.

---

### [INFO] `--allow-script-in-comments` Javadoc Flag

- **Location**: `build.gradle:125`
- Enables `<script>` tags in Javadoc source comments. Combined with the external analytics script, expands the XSS surface area of generated docs.

---

## Triaged Out

| Finding | Reason |
|---|---|
| Semgrep: `documentbuilderfactory-disallow-doctype-decl-missing` (SafeXmlUtils.java:107) | Shallow rule — does not recognize the `applyFeature()` conditional. Primary `disallow-doctype-decl` IS set before `newDocumentBuilder()`. Escalated to the bypass design issue (High finding above) instead. |
| Semgrep: `transformerfactory-dtds-not-disabled` (SafeXmlUtils.java:234) | `setAttribute(ACCESS_EXTERNAL_DTD, "")` is the correct API for `TransformerFactory` per OWASP. Rule expects `setFeature()`. Same bypass concern covered under High finding. |
| Semgrep: unsafe-reflection in `Field.fromJson()` (line 416) | Protected by `fieldNamePattern` regex guard at line 409. Not exploitable. |
| Semgrep: unsafe-reflection in `SwiftMessageUtils.createSequenceSingle()` (line 694) | `mt.getName()` is a `Class<? extends AbstractMT>` — class name comes from compile-time-verified type, not user input. |

---

## Residual Risk & Recommendations

**Highest priority**: The XXE bypass design (High) and the dead SAXParser protections (Medium) together mean `SafeXmlUtils.reader()` provides weaker-than-advertised XML safety for SAX-based parsing paths.

**Dependency SCA gap**: Java 11 toolchain unavailable — SpotBugs/FindSecBugs, which would catch insecure deserialization gadget chains and additional taint flows, could not run. Install JDK 11 and run:

```bash
./gradlew spotbugsMain
```

after adding `findsecbugs-plugin` to the SpotBugs config in `build.gradle`.

**Gradle lockfile**: Generate with `./gradlew dependencies --write-locks` to enable full transitive dependency SCA in future scans.

**SBOM**: The `sbom.cdx.json` at `/tmp/scan-results/prowide-core/` only contains CI/GitHub Actions components because syft could not resolve Java deps without a lockfile. Regenerate after adding the lockfile for a complete bill of materials.
