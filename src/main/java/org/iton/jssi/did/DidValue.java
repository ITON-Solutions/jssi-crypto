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

package org.iton.jssi.did;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;
import org.iton.jssi.util.Qualifiable;
import org.iton.jssi.util.Validatable;
import org.iton.jssi.util.ValidateException;

public class DidValue extends Qualifiable<DidValue> implements Validatable {

    private final static String PREFIX = "did";
    private String id;
    private String method;

    public DidValue(String entity){
        this.entity = entity;
    }

    public static DidValue create(String method, String entity){
        return new DidValue(qualify(PREFIX, method, entity));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    public ShortDidValue toShort() {
        return new ShortDidValue(entity);
    }

    public DidValue qualify(String method) {
        return setMethod(method);
    }

    public DidValue toUnqualified() {
        return new DidValue(toUnqualified(entity));
    }

    @Override
    public DidValue setMethod(String method) {
        return new DidValue(qualify(PREFIX, method, entity));
    }

    @Override
    public void validate() throws ValidateException {

        if(isFullyQualified(entity)){
            return;
        } else {
            try {
                byte[] decoded = Base58.decode(entity);
                if(decoded.length != 16 || decoded.length != 32){
                    throw new ValidateException(String.format(("Trying to use DID with unexpected length: %d. The 16- or 32-byte number upon which a DID is based should be 22/23 or 44/45 bytes when encoded as base58."), decoded.length));
                }
            } catch(AddressFormatException e){
                throw new ValidateException(e.getMessage());
            }

        }
    }

    public boolean  isAbbreviatable() {
        if(method != null){
            return method.startsWith("sov");
        }
        return true;
    }
}
