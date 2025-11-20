/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fido.uaf.server.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * UAF Server configuration holder.
 * This class holds server configuration values and makes them accessible
 * to non-Spring managed classes (POJOs) via static methods.
 */
@Component
public class UafServerConfig {

    /**
     * Get the server endpoint URL
     */
    @Getter
    private static String endpoint;
    /**
     * Get the facetId: android:apk-key-hash:xxxxxxxx
     */
    @Getter
    private static String facetId;
    /**
     * Get the trusted facets URL path
     *
     * @return trusted facets URL path (e.g., "/fidouaf/v1/public/uaf/facets")
     */
    @Getter
    private static String trustedFacetsUrl;

    @Value("${uaf.server.endpoint}")
    public void setEndpoint(String endpoint) {
        UafServerConfig.endpoint = endpoint;
    }

    @Value("${uaf.server.facetId}")
    public void setFacetId(String facetId) {
        UafServerConfig.facetId = facetId;
    }

    @Value("${uaf.server.trustedFacetsUrl}")
    public void setTrustedFacetsUrl(String url) {
        UafServerConfig.trustedFacetsUrl = url;
    }

    /**
     * Get the complete AppID (endpoint + facets URL)
     *
     * @return complete AppID URL
     */
    public static String getAppId() {
        return endpoint + trustedFacetsUrl;
    }
}
