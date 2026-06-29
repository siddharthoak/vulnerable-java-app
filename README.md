# vulnerable-java-app

An intentionally vulnerable Java 7 Maven application used to validate security scanner tooling (OWASP Dependency-Check, Trivy, Grype). All vulnerable dependencies are pinned to exact versions known to carry critical or high-severity CVEs. **Do not deploy this application.**

## Purpose

This repo exists to give the `security-scan.yml` GitHub Actions workflow a realistic target with known findings, so scanner output can be verified and the `vuln-remediation-agent` has real CVEs to fix.

---

## Dependency Upgrade Matrix

| **Component / Library** | **Vulnerable Version** | **CVE IDs** | **Severity** | **Description** | **Safe Version** |
| :---------------------- | :--------------------- | :---------- | :----------- | :-------------- | :--------------- |
| `log4j:log4j` | 1.2.17 | CVE-2021-4104 | High | JMSAppender performs JNDI lookups when a remote attacker controls the logged message, enabling RCE when JMS is configured. | 1.2.17 reached EOL — migrate to `log4j-core` 2.20.0+ |
| `org.apache.logging.log4j:log4j-core` | 2.14.1 | CVE-2021-44228 | Critical | **Log4Shell** — JNDI injection via `${jndi:...}` in any logged string allows unauthenticated RCE against any application that logs attacker-controlled input. | 2.20.0 |
| `commons-collections:commons-collections` | 3.2.1 | CVE-2015-6420 | High | `InvokerTransformer` chain enables arbitrary method invocation during Java deserialization of untrusted data. Exploited by the Apache Commons Collections gadget chain. | 3.2.2 |
| `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | CVE-2019-14379 | High | `enableDefaultTyping()` allows an attacker to trigger instantiation of arbitrary classes via a crafted JSON payload containing a type discriminator field. | 2.15.2 |
| `org.apache.struts:struts2-core` | 2.3.30 | CVE-2017-5638 | Critical | **Struts2 RCE** — improper OGNL expression evaluation in the Jakarta Multipart parser when processing a malformed `Content-Type` header. Exploited in the Equifax breach. | 6.3.0.2 |
| `org.springframework:spring-core` | 4.3.0.RELEASE | CVE-2022-22965 | Critical | **Spring4Shell** — RCE via data binding on JDK 9+ with a Servlet 3.1+ container. Attacker sets `class.classLoader.resources.context.parent.pipeline.first.*` properties to write a JSP webshell. | 5.3.27 |
| `commons-fileupload:commons-fileupload` | 1.3.1 | CVE-2016-1000031 | Critical | `DiskFileItem` deserialization allows RCE when an attacker can provide a crafted serialized `DiskFileItem` object to any endpoint that deserializes file upload data. | 1.5 |
| `mysql:mysql-connector-java` | 5.1.35 | CVE-2018-3258 | High | A crafted JDBC URL causes the connector to deserialize a server-provided object during connection setup, enabling RCE if an attacker can influence the connection URL. | 8.0.33 |

---

## Project Structure

```
vulnerable-java-app/
├── pom.xml                          Maven build — 8 vulnerable deps, Java 7 target
├── src/main/java/com/neurealm/vulndemo/
│   ├── App.java                     Log4j 1.x logger, commons-collections gadget, JDBC/MySQL
│   └── WebHandler.java              Jackson enableDefaultTyping(), Struts2, Spring, commons-fileupload
└── .github/workflows/
    └── security-scan.yml            OWASP DC + Trivy + Grype scan on PR
```

## How to build

```bash
mvn validate          # confirm pom.xml is well-formed
mvn dependency:tree   # confirm all 8 vulnerable deps resolve
mvn clean install -DskipTests
```

## Security scan (local)

```bash
# Trivy
trivy fs . --severity CRITICAL,HIGH

# Grype
grype dir:.
```

The `.github/workflows/security-scan.yml` workflow runs all three scanners automatically on every pull request targeting `main` and posts a summary comment with counts by severity.
