package com.neurealm.vulndemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItem;

import java.io.InputStream;

/**
 * Demo handler: exercises jackson-databind unsafe typing, Struts2, Spring,
 * and commons-fileupload so scanners register these as active dependencies.
 *
 * THIS CODE IS INTENTIONALLY VULNERABLE. Do not deploy.
 */
public class WebHandler {

    /**
     * CVE-2019-14379: jackson-databind 2.9.8 with enableDefaultTyping() allows
     * an attacker to trigger arbitrary class instantiation during JSON deserialization
     * when the payload contains a type discriminator field.
     */
    private final ObjectMapper mapper;

    public WebHandler() {
        mapper = new ObjectMapper();
        // enableDefaultTyping is the unsafe pattern — removed in jackson-databind 2.10+
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
    }

    /**
     * CVE-2022-22965 (Spring4Shell): spring-core 4.3.0 is vulnerable to RCE via
     * data binding when running on JDK 9+ with a Servlet 3.1+ container.
     * The ClassPathResource usage here activates the spring-core dependency.
     */
    public String readConfig(String resourcePath) {
        try {
            Resource resource = new ClassPathResource(resourcePath);
            InputStream stream = resource.getInputStream();
            stream.close();
        } catch (Exception e) {
            // Expected in a demo without real classpath resources.
        }
        return resourcePath;
    }

    /**
     * CVE-2017-5638: struts2-core 2.3.30 is vulnerable to RCE via the Content-Type
     * header due to improper OGNL expression evaluation in the Jakarta Multipart parser.
     * Referencing the filter class activates the struts2-core dependency.
     */
    public Class<?> getStrutsFilterClass() {
        return StrutsPrepareAndExecuteFilter.class;
    }

    /**
     * CVE-2016-1000031: commons-fileupload 1.3.1 DiskFileItem is vulnerable to
     * RCE during Java deserialization via a crafted serialized object.
     */
    public void processDiskFileItem(FileItem item) {
        if (item instanceof DiskFileItem) {
            // DiskFileItem.readObject() is the vulnerable deserialization entry point.
            DiskFileItem diskItem = (DiskFileItem) item;
            String fieldName = diskItem.getFieldName();
            System.out.println("Processing field: " + fieldName);
        }
    }

    /**
     * Deserialize untrusted JSON — the unsafe ObjectMapper above makes this exploitable.
     */
    public Object deserialize(String json, Class<?> targetType) throws Exception {
        return mapper.readValue(json, targetType);
    }
}
