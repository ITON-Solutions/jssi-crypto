/*
 *
 *  The MIT License
 *
 *  Copyright 2019 ITON Solutions.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

package org.iton.jssi.util;

import java.lang.reflect.InvocationTargetException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class Qualifiable<T> {

    private static Pattern PATTERN = Pattern.compile("^[a-z0-9]+:([a-z0-9]+):(.*)$");
    public String entity;

    public abstract String getPrefix();
    public abstract T setMethod(String method);

    public String getMethod() {
        return getMethod(entity);
    }

    public static String qualify(String prefix, String method, String id) {
        return String.format("%s:%s:%s", prefix, method, id);
    }

    public static String getMethod(String entity) {
        Matcher matcher = PATTERN.matcher(entity);
        if(matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    public boolean isFullyQualified(String entity) {
        Matcher matcher = PATTERN.matcher(entity);
        return matcher.matches();
    }

    public static String toUnqualified(String entity) {
        Matcher matcher = PATTERN.matcher(entity);
        if(matcher.find()) {
            return matcher.group(2);
        }
        return entity;

    }
}
