/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.signerattributesV2;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AttributeCertificate;

public class SignedAssertions extends ASN1Object {

    //private final Attribute[] assertions;
    private final List<SignedAssertion> assertions;

    public static SignedAssertions getInstance(Object obj) {
        if (obj instanceof AttributeCertificate) {
            return (SignedAssertions) obj;
        } else if (obj != null) {
            return new SignedAssertions(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public SignedAssertions(List<SignedAssertion> assertions) {

        int index = 0;
        //this.assertions = new Attribute[assertions.size()];
        this.assertions = assertions;

        for (SignedAssertion assertion : assertions) {
            //Attribute attribute = new org.bouncycastle.asn1.cms.Attribute(new ASN1ObjectIdentifier("0.4.0.19122.1.6"),
            //        new DERSet(assertion));
            //this.assertions[index++] = assertion;
        }

    }

    private SignedAssertions(ASN1Sequence seq) {

        int index = 0;
        //assertions = new Attribute[seq.size()];
        //assertions = new SignedAssertion[seq.size()];
        assertions = new ArrayList<>(seq.size());
        for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
            //assertions[index++] = Attribute.getInstance(e.nextElement());
            //assertions[index++] = SignedAssertion.getInstance(e.nextElement());
            assertions.add(SignedAssertion.getInstance(e.nextElement()));
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {

        ASN1EncodableVector v = new ASN1EncodableVector();
        /*
        for (int i = 0; i != assertions.length; i++) {

            v.add(assertions[i]);
        }
        
        
         */
        for (SignedAssertion sa : assertions) {
            v.add(sa);
        }

        return new DERSequence(v);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        /*
        
        for (int i = 0; i != assertions.length; i++) {

            
            final ASN1Set attrValues = assertions[i].getAttrValues();
            final ASN1Encodable attrValue = attrValues.getObjectAt(0);

            final SignedAssertion sa = SignedAssertion.getInstance(attrValue);
            
            SignedAssertion sa = assertions[i];
            sb.append(sa.toString()).append("\n");
        }
         */
        for (SignedAssertion sa : assertions) {
            sb.append(sa.toString()).append("\n");
        }

        return sb.toString();
    }

    public List<SignedAssertion> getAssertions() {
        return assertions;
    }
}
