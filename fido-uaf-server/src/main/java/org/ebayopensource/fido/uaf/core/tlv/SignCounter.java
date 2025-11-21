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

package org.ebayopensource.fido.uaf.core.tlv;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.logging.Logger;

/**
 * SignCounter 數據解析工具類
 * <p>
 * 負責解析 FIDO UAF 協議中的 Counter 數據格式：
 * - 註冊階段：8 bytes (4 bytes signature counter + 4 bytes registration counter)
 * - 認證階段：4 bytes (signature counter only)
 * <p>
 * Counter 使用 little-endian 格式的 unsigned 32-bit integer
 */
public class SignCounter {

    private static final Logger logger = Logger.getLogger(SignCounter.class.getName());

    /**
     * 從註冊階段的 8 bytes counter 中提取並格式化為字串
     *
     * @param counterBytes 8 bytes 的 counter array (signature counter + registration counter)
     * @return 格式化的字串 "signatureCounter.registrationCounter"，例如 "0.1" 或 "1.0"
     * @throws IllegalArgumentException 如果 counterBytes 長度不是 8
     */
    public static String formatRegistrationCounter(byte[] counterBytes) {
        if (counterBytes == null || counterBytes.length != 8) {
            throw new IllegalArgumentException("Registration counter must be 8 bytes, got: " +
                    (counterBytes == null ? "null" : counterBytes.length));
        }

        long signatureCounter = extractSignatureCounter(counterBytes);
        long registrationCounter = extractRegistrationCounter(counterBytes);

        return signatureCounter + "." + registrationCounter;
    }

    /**
     * 從儲存的 counter 字串中提取 registration counter
     *
     * @param storedCounter 儲存的 counter 字串（格式："signatureCounter.registrationCounter"）
     * @return registration counter 值，如果格式不符則返回 0
     */
    public static long parseStoredRegistrationCounter(String storedCounter) {
        if (storedCounter == null || storedCounter.isEmpty()) {
            return 0;
        }

        try {
            // 如果包含 "."，則提取 registration counter（第二部分）
            if (storedCounter.contains(".")) {
                String[] parts = storedCounter.split("\\.");
                if (parts.length >= 2) {
                    return Long.parseLong(parts[1]);
                }
            }
            // 如果沒有 "."，表示是舊格式（只有 signature counter），registration counter 為 0
            return 0;
        } catch (NumberFormatException e) {
            logger.warning("Failed to parse stored registration counter: " + storedCounter);
            return 0;
        }
    }

    /**
     * 從 counter bytes 中提取 signature counter（前 4 bytes）
     *
     * @param counterBytes counter 的 byte array（4 或 8 bytes）
     * @return signature counter 值（unsigned int 轉為 long）
     */
    public static long extractSignatureCounter(byte[] counterBytes) {
        if (counterBytes == null || counterBytes.length < 4) {
            throw new IllegalArgumentException("Counter bytes must be at least 4 bytes");
        }

        // FIDO UAF 使用 little-endian 格式
        ByteBuffer buffer = ByteBuffer.wrap(counterBytes, 0, 4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        // Java 沒有 unsigned int，所以用 long 儲存
        // 使用 & 0xFFFFFFFFL 轉換為 unsigned
        return buffer.getInt() & 0xFFFFFFFFL;
    }

    /**
     * 從 8 bytes counter 中提取 registration counter（後 4 bytes）
     *
     * @param counterBytes 8 bytes 的 counter array
     * @return registration counter 值
     */
    public static long extractRegistrationCounter(byte[] counterBytes) {
        if (counterBytes == null || counterBytes.length < 8) {
            return 0;
        }

        ByteBuffer buffer = ByteBuffer.wrap(counterBytes, 4, 4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        return buffer.getInt() & 0xFFFFFFFFL;
    }

    /**
     * 解析儲存在資料庫中的 counter 字串
     *
     * @param storedCounter 儲存的 counter 字串（格式："signatureCounter.registrationCounter" 或 "signatureCounter"）
     * @return signature counter 值
     */
    public static long parseStoredCounter(String storedCounter) {
        if (storedCounter == null || storedCounter.isEmpty()) {
            return 0;
        }

        try {
            // 如果包含 "."，則是註冊時的格式 "signatureCounter.registrationCounter"
            if (storedCounter.contains(".")) {
                String[] parts = storedCounter.split("\\.");
                return Long.parseLong(parts[0]);
            } else {
                // 否則直接解析為 signatureCounter
                return Long.parseLong(storedCounter);
            }
        } catch (NumberFormatException e) {
            logger.warning("Failed to parse stored counter: " + storedCounter);
            return 0;
        }
    }
}
