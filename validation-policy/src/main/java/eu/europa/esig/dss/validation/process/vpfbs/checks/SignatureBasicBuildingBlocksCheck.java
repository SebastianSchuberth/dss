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
package eu.europa.esig.dss.validation.process.vpfbs.checks;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignatures;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;

public class SignatureBasicBuildingBlocksCheck extends ChainItem<XmlValidationProcessBasicSignatures> {

	private final DiagnosticData diagnosticData;

	private final XmlBasicBuildingBlocks signatureBBB;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	private Indication indication;
	private SubIndication subIndication;
	private List<XmlName> errors = new ArrayList<XmlName>();

	public SignatureBasicBuildingBlocksCheck(XmlValidationProcessBasicSignatures result, DiagnosticData diagnosticData, XmlBasicBuildingBlocks signatureBBB,
			Map<String, XmlBasicBuildingBlocks> bbbs, LevelConstraint constraint) {
		super(result, constraint, signatureBBB.getId());

		this.diagnosticData = diagnosticData;
		this.signatureBBB = signatureBBB;
		this.bbbs = bbbs;
		
		result.setProofOfExistence(getCurrentTime());
	}
	
	private XmlProofOfExistence getCurrentTime() {
		XmlProofOfExistence proofOfExistence = new XmlProofOfExistence();
		proofOfExistence.setTime(diagnosticData.getValidationDate());
		return proofOfExistence;
	}

	@Override
	protected boolean process() {
		

		/*
		 * 1) Token signature validation: the building block shall perform the validation process for Basic Signatures
		 * as per clause 5.3 with the time-stamp token. In all the steps of this process, the building block shall take
		 * into account that the signature to validate is a time-stamp token (e.g. to select TSA trust-anchors). If this
		 * step
		 * returns PASSED, the building block shall go to the next step. Otherwise, the building block shall return the
		 * indication and information returned by the validation process.
		 */
		XmlFC fc = signatureBBB.getFC();
		if (fc != null) {
			XmlConclusion fcConclusion = fc.getConclusion();
			if (!Indication.PASSED.equals(fcConclusion.getIndication())) {
				indication = Indication.FAILED;
				subIndication = SubIndication.FORMAT_FAILURE;
				errors.addAll(fcConclusion.getErrors());
				return false;
			}
		}

		/*
		 * 5.3.4 2) The Basic Signature validation process shall perform the identification of the signing certificate
		 * (as per clause 5.2.3) with the signature and the signing certificate, if provided as a parameter.
		 * 
		 * If the identification of the signing certificate process returns the indication INDETERMINATE with the
		 * sub-indication NO_SIGNING_CERTIFICATE_FOUND, the Basic Signature validation process shall return the
		 * indication INDETERMINATE with the sub-indication NO_SIGNING_CERTIFICATE_FOUND,
		 * 
		 * otherwise it shall go to the next step.
		 */
		XmlISC isc = signatureBBB.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (Indication.INDETERMINATE.equals(iscConclusion.getIndication())
				&& SubIndication.NO_SIGNING_CERTIFICATE_FOUND.equals(iscConclusion.getSubIndication())) {
			indication = iscConclusion.getIndication();
			subIndication = iscConclusion.getSubIndication();
			errors.addAll(iscConclusion.getErrors());
			return false;
		}

		/*
		 * 5.3.4 3) The Basic Signature validation process shall perform the Validation Context Initialization as per
		 * clause 5.2.4.
		 * 
		 * If the process returns INDETERMINATE with some sub-indication, return with the indication INDETERMINATE
		 * together with that sub-indication,
		 * 
		 * otherwise go to the next step.
		 */
		XmlVCI vci = signatureBBB.getVCI();
		if (vci != null) {
			XmlConclusion vciConclusion = vci.getConclusion();
			if (Indication.INDETERMINATE.equals(vciConclusion.getIndication())) {
				indication = vciConclusion.getIndication();
				subIndication = vciConclusion.getSubIndication();
				errors.addAll(vciConclusion.getErrors());
				return false;
			}
		}

		/*
		 * 5.3.4 4) The Basic Signature validation process shall perform the X.509 Certificate Validation as per clause
		 * 5.2.6 with the following inputs:
		 * 
		 * a) The signing certificate obtained in step 2. And
		 * b) X.509 validation constraints, certificate validation-data and cryptographic constraints
		 * obtained in step 3 or provided as input.
		 * 
		 * If the signing certificate validation process returns the indication PASSED, the Basic Signature validation
		 * process shall go to the next step.
		 * 
		 * If the signing certificate validation process returns the indication INDETERMINATE with the sub-indication
		 * REVOKED_NO_POE and if the signature contains a content-time-stamp attribute, the Basic Signature validation
		 * process shall perform the validation process for AdES time-stamps as defined in clause 5.4. If this process
		 * returns the indication PASSED and the generation time of the time-stamp token is after the revocation time,
		 * the Basic Signature validation process shall return the indication FAILED with the sub-indication REVOKED.
		 * In all other cases, the Basic Signature validation process shall set
		 * X509_validation-status to INDETERMINATE with the sub-indication REVOKED_NO_POE. The process shall
		 * continue with step 5. 
		 */
		XmlXCV xcv = signatureBBB.getXCV();
		XmlConclusion x509ValidationStatus = null;
		if (xcv != null) {
			XmlConclusion xcvConclusion = x509ValidationStatus = xcv.getConclusion();
			if (Indication.INDETERMINATE.equals(xcvConclusion.getIndication()) && SubIndication.REVOKED_NO_POE.equals(xcvConclusion.getSubIndication())) {
				SignatureWrapper currentSignature = diagnosticData.getSignatureById(signatureBBB.getId());
				List<TimestampWrapper> contentTimestamps = currentSignature.getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
				if (Utils.isCollectionNotEmpty(contentTimestamps)) {
					boolean failed = false;
					Date revocationDate = getRevocationDateForSigningCertificate(currentSignature);
					for (TimestampWrapper timestamp : contentTimestamps) {
						if (isValidTimestamp(timestamp)) {
							Date tspProductionTime = timestamp.getProductionTime();
							if (tspProductionTime.after(revocationDate)) {
								failed = true;
								break;
							}
						}
					}

					if (failed) {
						x509ValidationStatus.setIndication(Indication.FAILED);
						x509ValidationStatus.setSubIndication(SubIndication.REVOKED);
						errors.addAll(xcvConclusion.getErrors());
					}
				}

				x509ValidationStatus.setIndication(Indication.INDETERMINATE);
				x509ValidationStatus.setSubIndication(SubIndication.REVOKED_NO_POE);
				errors.addAll(xcvConclusion.getErrors());

			}
			/*
			 * If the signing certificate validation process returns the indication
			 * INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NO_POE and if the
			 * signature contains a content-time-stamp attribute, the Basic Signature
			 * validation process shall perform the validation process for AdES time-stamps
			 * as defined in clause 5.4. If it returns the indication PASSED and the
			 * generation time of the time-stamp token is after the expiration date of the
			 * signing certificate, the Basic Signature validation process shall return the
			 * indication INDETERMINATE with the sub-indication EXPIRED. Otherwise, the
			 * Basic Signature validation process shall set X509_validation-status to
			 * INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NO_POE. The process shall
			 * continue with step 5.
			 */
			else if (Indication.INDETERMINATE.equals(xcvConclusion.getIndication())
					&& SubIndication.OUT_OF_BOUNDS_NO_POE.equals(xcvConclusion.getSubIndication())) {
				SignatureWrapper currentSignature = diagnosticData.getSignatureById(signatureBBB.getId());
				List<TimestampWrapper> contentTimestamps = currentSignature.getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
				if (Utils.isCollectionNotEmpty(contentTimestamps)) {
					boolean failed = false;
					Date expirationDate = getExpirationDateForSigningCertificate(currentSignature);
					for (TimestampWrapper timestamp : contentTimestamps) {
						if (isValidTimestamp(timestamp)) {
							Date tspProductionTime = timestamp.getProductionTime();
							if (tspProductionTime.after(expirationDate)) {
								failed = true;
								break;
							}
						}
					}

					if (failed) {
						x509ValidationStatus.setIndication(Indication.INDETERMINATE);
						x509ValidationStatus.setSubIndication(SubIndication.EXPIRED);
						errors.addAll(xcvConclusion.getErrors());
					}
				}

				x509ValidationStatus.setIndication(Indication.INDETERMINATE);
				x509ValidationStatus.setSubIndication(SubIndication.OUT_OF_BOUNDS_NO_POE);
				errors.addAll(xcvConclusion.getErrors());

			}
			/*
			 * In all other cases, the Basic Signature validation process shall return the
			 * indication, sub-indication and any associated information returned by the
			 * signing certificate validation process.
			 */
			else if (!Indication.PASSED.equals(xcvConclusion.getIndication())) {
				indication = xcvConclusion.getIndication();
				subIndication = xcvConclusion.getSubIndication();
				errors.addAll(xcvConclusion.getErrors());
				return false;
			}
		}

		/*
		 * 5.3.4 5) The Basic Signature validation process shall perform the Cryptographic Verification process as per
		 * clause 5.2.7 with the following inputs:
		 * 
		 * a) The signed data object(s).
		 * b) The certificate chain returned in the previous step. And
		 * c) The SD or SDR.
		 * 
		 * If the cryptographic signature validation process returns PASSED:
		 * a) If the X509_validation-status set in the previous step contains the indication PASSED, the Basic
		 * Signature validation process shall go to the next step;
		 * b) If the X509_validation-status set in the previous step contains the indication INDETERMINATE or
		 * FAILED with any subindication, the Basic Signature validation process shall return the indication and
		 * subindication contained in X509_validation-status, with any associated information about the reason. 
		 * 
		 * Otherwise, the Basic Signature validation process shall return the returned indication, sub-indication and
		 * associated information provided by the cryptographic signature validation process.
		 */
		XmlCV cv = signatureBBB.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (Indication.PASSED.equals(cvConclusion.getIndication())) {
			if (x509ValidationStatus != null && !Indication.PASSED.equals(x509ValidationStatus.getIndication())) {
				indication = x509ValidationStatus.getIndication();
				subIndication = x509ValidationStatus.getSubIndication();
				return false;
			}
		} else {
			indication = cvConclusion.getIndication();
			subIndication = cvConclusion.getSubIndication();
			errors.addAll(cvConclusion.getErrors());
			return false;
		}

		/*
		 * 5.3.4 6) The Basic Signature validation process shall perform the Signature Acceptance Validation process as
		 * per clause 5.2.8 with the following inputs:
		 * a) the Signed Data Object(s);
		 * b) the certificate chain obtained in step 4;
		 * c) the Cryptographic Constraints; and
		 * d) the Signature Elements Constraints. 
		 * 
		 * If the signature acceptance validation process returns PASSED, the Basic Signature validation process shall
		 * go to the next step.
		 * 
		 * If the signature acceptance validation process returns the indication INDETERMINATE with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the material concerned by this failure is the signature value and if
		 * the signature contains a content-time-stamp attribute, the Basic Signature validation process shall perform
		 * the validation process for AdES time-stamps as defined in clause 5.4. If it returns the indication PASSED and
		 * the algorithm(s) concerned were no longer considered reliable at the generation time of the timestamp token,
		 * the Basic Signature validation process shall return the indication INDETERMINATE with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE. In all other cases, the Basic Signature validation process shall return the
		 * indication INDETERMINATE with the sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 * 
		 * NOTE 2: The content time-stamp is a signed attribute and hence proves that the signature value was produced
		 * after the generation time of the time-stamp token.
		 * NOTE 3: In case this clause returns INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, the validation process
		 * for signature with long-term validation data and with archival data can be used to validate the signature, if
		 * other POE (e.g. from a trusted archive) exist.
		 *
		 * In all other cases, the Basic Signature validation process shall return the indication and associated
		 * information returned by the signature acceptance validation building block.
		 */
		XmlSAV sav = signatureBBB.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (Indication.INDETERMINATE.equals(savConclusion.getIndication())
				&& SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(savConclusion.getSubIndication())) {

			SignatureWrapper currentSignature = diagnosticData.getSignatureById(signatureBBB.getId());
			List<TimestampWrapper> contentTimestamps = currentSignature.getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
			if (Utils.isCollectionNotEmpty(contentTimestamps)) {
				boolean failed = false;
				for (TimestampWrapper timestamp : contentTimestamps) {
					if (isValidTimestamp(timestamp)) {
						failed = true;
						break;
					}
				}

				if (failed) {
					indication = Indication.INDETERMINATE;
					subIndication = SubIndication.CRYPTO_CONSTRAINTS_FAILURE;
					return false;
				}
			}

			indication = Indication.INDETERMINATE;
			subIndication = SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
			errors.addAll(savConclusion.getErrors());
			return false;

		} else if (!Indication.PASSED.equals(savConclusion.getIndication())) {
			indication = savConclusion.getIndication();
			subIndication = savConclusion.getSubIndication();
			errors.addAll(savConclusion.getErrors());
			return false;
		}

		return true;
	}

	private boolean isValidTimestamp(TimestampWrapper timestamp) {
		XmlBasicBuildingBlocks timestampBasicBuildingBlocks = bbbs.get(timestamp.getId());
		return (timestampBasicBuildingBlocks != null && timestampBasicBuildingBlocks.getConclusion() != null)
				&& Indication.PASSED.equals(timestampBasicBuildingBlocks.getConclusion().getIndication());
	}

	private Date getRevocationDateForSigningCertificate(SignatureWrapper currentSignature) {
		CertificateWrapper signingCertificate = currentSignature.getSigningCertificate();
		if (signingCertificate != null && Utils.isCollectionNotEmpty(signingCertificate.getCertificateRevocationData())) {
			return diagnosticData.getLatestRevocationDataForCertificate(signingCertificate).getRevocationDate();
		}
		return null;
	}

	private Date getExpirationDateForSigningCertificate(SignatureWrapper currentSignature) {
		CertificateWrapper signingCertificate = currentSignature.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.getNotAfter();
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_ROBVPIIC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_ROBVPIIC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

	@Override
	protected List<XmlName> getPreviousErrors() {
		return errors;
	}

}
