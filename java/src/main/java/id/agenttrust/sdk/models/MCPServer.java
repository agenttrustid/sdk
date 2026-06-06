package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a registered MCP (Model Context Protocol) server.
 */
public class MCPServer {

    private final String id;
    private final String name;
    private final String url;
    private final List<String> capabilities;
    private final String orgId;
    private final String createdAt;

    public MCPServer(String id, String name, String url, List<String> capabilities,
                     String orgId, String createdAt) {
        this.id = id;
        this.name = name;
        this.url = url;
        this.capabilities = capabilities != null
                ? Collections.unmodifiableList(new ArrayList<>(capabilities))
                : Collections.emptyList();
        this.orgId = orgId;
        this.createdAt = createdAt;
    }

    /** @return the MCP server identifier */
    public String getId() { return id; }

    /** @return the human-readable server name */
    public String getName() { return name; }

    /** @return the server's connection URL */
    public String getUrl() { return url; }

    /** @return capabilities advertised by the server */
    public List<String> getCapabilities() { return capabilities; }

    /** @return the organization that registered this server */
    public String getOrgId() { return orgId; }

    /** @return when the server was registered (ISO 8601 string) */
    public String getCreatedAt() { return createdAt; }

    /**
     * @param data parsed JSON object
     * @return the parsed server, or {@code null} if {@code data} is {@code null}
     */
    public static MCPServer fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        String orgId = JsonUtil.getString(data, "org_id");
        if (orgId == null) {
            orgId = JsonUtil.getString(data, "orgId");
        }
        String createdAt = JsonUtil.getString(data, "created_at");
        if (createdAt == null) {
            createdAt = JsonUtil.getString(data, "createdAt");
        }
        return new MCPServer(
                JsonUtil.getString(data, "id"),
                JsonUtil.getString(data, "name"),
                JsonUtil.getString(data, "url"),
                JsonUtil.getStringList(data, "capabilities"),
                orgId,
                createdAt
        );
    }

    /** @return mutable map representation suitable for JSON serialization */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (id != null) map.put("id", id);
        if (name != null) map.put("name", name);
        if (url != null) map.put("url", url);
        map.put("capabilities", new ArrayList<Object>(capabilities));
        if (orgId != null) map.put("org_id", orgId);
        if (createdAt != null) map.put("created_at", createdAt);
        return map;
    }

    @Override
    public String toString() {
        return "MCPServer{id='" + id + "', name='" + name + "'}";
    }
}
