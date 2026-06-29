package com.neurealm.vulndemo;

import org.apache.log4j.Logger;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.DriverManager;

/**
 * Demo app: exercises log4j 1.x, commons-collections deserialization gadget,
 * and MySQL JDBC driver so scanners register these as active dependencies.
 *
 * THIS CODE IS INTENTIONALLY VULNERABLE. Do not deploy.
 */
public class App {

    // CVE-2021-4104: log4j 1.x JMSAppender can perform JNDI lookups when a
    // remote attacker controls the logged message.
    private static final Logger logger = Logger.getLogger(App.class);

    public static void main(String[] args) {
        logger.info("Starting vulnerable-java-app demo");

        demonstrateDeserializationGadget();
        demonstrateJdbcSetup();

        logger.info("Demo complete");
    }

    /**
     * CVE-2015-6420: commons-collections 3.2.1 InvokerTransformer allows an
     * attacker to execute arbitrary methods during Java deserialization.
     * This chain is the canonical proof-of-concept gadget.
     */
    private static void demonstrateDeserializationGadget() {
        // Build the InvokerTransformer chain — the deserialization gadget.
        Transformer[] chain = new Transformer[] {
            new ConstantTransformer("demo-value"),
            new InvokerTransformer(
                "toString", new Class[]{}, new Object[]{}
            ),
        };
        ChainedTransformer transformer = new ChainedTransformer(chain);

        // Simulate reading serialized bytes from an untrusted source.
        byte[] fakeSerializedBytes = new byte[]{};
        try (ObjectInputStream ois =
                new ObjectInputStream(new ByteArrayInputStream(fakeSerializedBytes))) {
            Object obj = ois.readObject();
            // In a real exploit the serialized payload would invoke the chain above.
            transformer.transform(obj);
        } catch (Exception e) {
            // Expected — fakeSerializedBytes is empty; we only need the import active.
            logger.debug("Deserialization demo (expected exception): " + e.getClass().getName());
        }
    }

    /**
     * CVE-2018-3258: mysql-connector-java 5.1.35 allows RCE via a crafted JDBC
     * URL that triggers object deserialization during connection setup.
     */
    private static void demonstrateJdbcSetup() {
        try {
            // Force-load the vulnerable MySQL driver.
            Class.forName("com.mysql.jdbc.Driver");

            // Attempt a connection — will fail on a demo machine (no DB),
            // but the driver class is loaded and the CVE surface is exercised.
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/vulndemo", "root", "");
            conn.close();
        } catch (Exception e) {
            logger.debug("JDBC demo (expected on demo machine): " + e.getClass().getName());
        }
    }
}
