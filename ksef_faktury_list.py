#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2025
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
"""
Standalone script for fetching invoices from KSeF (Krajowy System e-Faktur).

KSeF is the Polish National e-Invoice System (Krajowy System e-Faktur).
This script uses XAdES-BES digital signature authentication with a qualified certificate.

Usage:
    python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password secret
    python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password-file haslo.txt
    python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem  # No password if key is not encrypted

Options:
    --nip           NIP of the entity (required)
    --cert          Path to certificate file (PEM format)
    --key           Path to private key file (PEM format)
    --password      Password for encrypted private key
    --password-file File containing password for private key
    --env           Environment: test, demo, prod (default: prod)
    --date-from     Start date YYYY-MM-DD (default: 30 days ago)
    --date-to       End date YYYY-MM-DD (default: today)
    --subject-type  Subject1 (issued/sales) or Subject2 (received/purchases), default: Subject2
    --output        Output format: table, json, xml (default: table)
    --download-xml  Download full XML for each invoice
    --verbose       Enable verbose logging
"""

import argparse
import base64
import datetime
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from typing import Optional

import requests
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.backends import default_backend

# KSeF API URLs
KSEF_URLS = {
    'test': 'https://api-test.ksef.mf.gov.pl/v2',
    'demo': 'https://api-demo.ksef.mf.gov.pl/v2',
    'prod': 'https://api.ksef.mf.gov.pl/v2',
}

logger = logging.getLogger(__name__)


class KSeFError(Exception):
    """Exception for KSeF API errors."""
    def __init__(self, message: str, status_code: int = None, response_data: dict = None):
        self.message = message
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(self.message)


class KSeFClient:
    """
    Standalone KSeF API client with XAdES authentication.
    """

    def __init__(
        self,
        cert_path: str,
        key_path: str,
        key_password: str = None,
        environment: str = 'test',
        timeout: int = 30
    ):
        """
        Initialize KSeF client.

        Args:
            cert_path: Path to X.509 certificate (PEM format)
            key_path: Path to private key (PEM format)
            key_password: Password for encrypted private key
            environment: API environment ('test', 'demo', 'prod')
            timeout: Request timeout in seconds
        """
        if environment not in KSEF_URLS:
            raise ValueError(f"Unknown environment: {environment}. Available: {list(KSEF_URLS.keys())}")

        self.environment = environment
        self.base_url = KSEF_URLS[environment]
        self.timeout = timeout
        self.cert_path = cert_path
        self.key_path = key_path
        self._key_password = key_password

        # Session tokens
        self.authentication_token = None
        self.access_token = None
        self.refresh_token = None
        self.reference_number = None

        # Loaded certificate and key (lazy loading)
        self._certificate = None
        self._private_key = None

    def _load_certificate(self) -> x509.Certificate:
        """Load X.509 certificate."""
        if self._certificate is None:
            if not os.path.exists(self.cert_path):
                raise KSeFError(f"Certificate not found: {self.cert_path}")

            with open(self.cert_path, 'rb') as f:
                cert_data = f.read()

            try:
                self._certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            except Exception:
                self._certificate = x509.load_der_x509_certificate(cert_data, default_backend())

        return self._certificate

    def _load_private_key(self):
        """Load private key."""
        if self._private_key is None:
            if not os.path.exists(self.key_path):
                raise KSeFError(f"Private key not found: {self.key_path}")

            with open(self.key_path, 'rb') as f:
                key_data = f.read()

            password = self._key_password.encode() if self._key_password else None

            try:
                self._private_key = serialization.load_pem_private_key(
                    key_data, password=password, backend=default_backend()
                )
            except Exception as e:
                raise KSeFError(f"Error loading private key: {e}")

        return self._private_key

    def _der_to_raw_ecdsa(self, der_signature: bytes, key_size: int) -> bytes:
        """
        Convert ECDSA signature from DER format to raw (r || s) format.

        XML-DSig requires ECDSA signatures in raw format (IEEE P.1363).
        """
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        r, s = decode_dss_signature(der_signature)
        component_size = (key_size + 7) // 8
        r_bytes = r.to_bytes(component_size, byteorder='big')
        s_bytes = s.to_bytes(component_size, byteorder='big')

        return r_bytes + s_bytes

    def _get_headers(self, with_session: bool = True, content_type: str = 'application/json') -> dict:
        """Return HTTP headers for requests."""
        headers = {
            'Content-Type': content_type,
            'Accept': 'application/json',
        }
        if with_session and self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        elif with_session and self.authentication_token:
            headers['Authorization'] = f'Bearer {self.authentication_token}'
        return headers

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: dict = None,
        xml_data: str = None,
        with_session: bool = True,
        accept: str = 'application/json'
    ) -> dict:
        """
        Make request to KSeF API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without base_url)
            data: JSON data to send
            xml_data: XML data to send
            with_session: Whether to add session token to headers
            accept: Expected response format

        Returns:
            Response as dict

        Raises:
            KSeFError: On API error
        """
        url = f"{self.base_url}{endpoint}"

        if xml_data:
            content_type = 'application/xml; charset=utf-8'
        else:
            content_type = 'application/json'

        headers = self._get_headers(with_session, content_type)
        headers['Accept'] = accept

        logger.info(f"KSeF Request: {method} {url}")
        if data:
            logger.debug(f"KSeF Request data: {json.dumps(data, indent=2)}")

        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=self.timeout)
            elif method.upper() == 'POST':
                if xml_data:
                    response = requests.post(
                        url, headers=headers, data=xml_data.encode('utf-8'), timeout=self.timeout
                    )
                else:
                    response = requests.post(
                        url, headers=headers, json=data, timeout=self.timeout
                    )
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            logger.info(f"KSeF Response: {response.status_code}")
            logger.debug(f"KSeF Response body: {response.text[:2000] if response.text else 'EMPTY'}")

            content_type = response.headers.get('Content-Type', '')

            if response.status_code >= 400:
                error_msg = f"KSeF API Error: HTTP {response.status_code}"
                error_data = {}
                try:
                    if 'application/json' in content_type:
                        error_data = response.json()
                        if 'exception' in error_data:
                            exc = error_data['exception']
                            detail_list = exc.get('exceptionDetailList', [])
                            if detail_list:
                                error_msg = detail_list[0].get('exceptionDescription', error_msg)
                        elif 'message' in error_data:
                            error_msg = error_data['message']
                    else:
                        error_data = {'raw': response.text[:500], 'content_type': content_type}
                except json.JSONDecodeError:
                    error_data = {'raw': response.text[:500], 'content_type': content_type}

                raise KSeFError(
                    message=error_msg,
                    status_code=response.status_code,
                    response_data=error_data
                )

            if response.text:
                if 'application/json' in content_type:
                    return response.json()
                elif any(ct in content_type for ct in ['application/octet-stream', 'text/xml', 'application/xml']):
                    return {'raw_content': response.text}
                else:
                    try:
                        return response.json()
                    except json.JSONDecodeError:
                        return {'raw_content': response.text}
            return {}

        except requests.RequestException as e:
            logger.error(f"KSeF Request Error: {e}")
            raise KSeFError(message=f"Connection error with KSeF: {str(e)}")

    def _build_auth_token_request_xml(self, challenge: str, nip: str, timestamp: str) -> str:
        """
        Build AuthTokenRequest XML document.

        Args:
            challenge: Challenge from API
            nip: Entity NIP
            timestamp: Timestamp from challenge response

        Returns:
            XML as string (without signature)
        """
        NS = 'http://ksef.mf.gov.pl/auth/token/2.0'

        root = etree.Element('AuthTokenRequest', nsmap={None: NS})

        challenge_elem = etree.SubElement(root, 'Challenge')
        challenge_elem.text = challenge

        context_elem = etree.SubElement(root, 'ContextIdentifier')
        nip_elem = etree.SubElement(context_elem, 'Nip')
        nip_elem.text = nip

        subject_type_elem = etree.SubElement(root, 'SubjectIdentifierType')
        subject_type_elem.text = 'certificateSubject'

        return '<?xml version="1.0" encoding="utf-8"?>' + etree.tostring(root, encoding='unicode')

    def _sign_xml_xades(self, xml_content: str) -> str:
        """
        Sign XML document with XAdES-BES signature.

        Args:
            xml_content: XML to sign

        Returns:
            Signed XML as string
        """
        cert = self._load_certificate()
        private_key = self._load_private_key()

        doc = etree.fromstring(xml_content.encode('utf-8'))

        NS_DS = 'http://www.w3.org/2000/09/xmldsig#'
        NS_XADES = 'http://uri.etsi.org/01903/v1.3.2#'

        sig_id = f"Signature-{uuid.uuid4()}"
        signed_props_id = f"SignedProperties-{uuid.uuid4()}"

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode()
        cert_digest = base64.b64encode(hashlib.sha256(cert_der).digest()).decode()

        signing_time = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_keys
        if isinstance(private_key, rsa_keys.RSAPrivateKey):
            sig_algorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        else:
            sig_algorithm = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'

        # Build Signature structure
        signature = etree.Element('{%s}Signature' % NS_DS, nsmap={'ds': NS_DS}, Id=sig_id)

        signed_info = etree.SubElement(signature, '{%s}SignedInfo' % NS_DS)
        etree.SubElement(signed_info, '{%s}CanonicalizationMethod' % NS_DS,
                        Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')
        etree.SubElement(signed_info, '{%s}SignatureMethod' % NS_DS, Algorithm=sig_algorithm)

        # Reference to document
        ref1 = etree.SubElement(signed_info, '{%s}Reference' % NS_DS, URI='')
        transforms1 = etree.SubElement(ref1, '{%s}Transforms' % NS_DS)
        etree.SubElement(transforms1, '{%s}Transform' % NS_DS,
                        Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature')
        etree.SubElement(transforms1, '{%s}Transform' % NS_DS,
                        Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')
        etree.SubElement(ref1, '{%s}DigestMethod' % NS_DS, Algorithm='http://www.w3.org/2001/04/xmlenc#sha256')
        digest_val1 = etree.SubElement(ref1, '{%s}DigestValue' % NS_DS)

        # Reference to SignedProperties
        ref2 = etree.SubElement(signed_info, '{%s}Reference' % NS_DS,
                               URI=f'#{signed_props_id}',
                               Type='http://uri.etsi.org/01903#SignedProperties')
        transforms2 = etree.SubElement(ref2, '{%s}Transforms' % NS_DS)
        etree.SubElement(transforms2, '{%s}Transform' % NS_DS,
                        Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')
        etree.SubElement(ref2, '{%s}DigestMethod' % NS_DS, Algorithm='http://www.w3.org/2001/04/xmlenc#sha256')
        digest_val2 = etree.SubElement(ref2, '{%s}DigestValue' % NS_DS)

        # SignatureValue (empty)
        sig_value = etree.SubElement(signature, '{%s}SignatureValue' % NS_DS)

        # KeyInfo
        key_info = etree.SubElement(signature, '{%s}KeyInfo' % NS_DS)
        x509_data = etree.SubElement(key_info, '{%s}X509Data' % NS_DS)
        x509_cert = etree.SubElement(x509_data, '{%s}X509Certificate' % NS_DS)
        x509_cert.text = cert_b64

        # Object with QualifyingProperties
        object_elem = etree.SubElement(signature, '{%s}Object' % NS_DS)

        qualifying_properties = etree.SubElement(
            object_elem,
            '{%s}QualifyingProperties' % NS_XADES,
            nsmap={'xades': NS_XADES},
            Target=f'#{sig_id}'
        )
        signed_properties = etree.SubElement(
            qualifying_properties,
            '{%s}SignedProperties' % NS_XADES,
            Id=signed_props_id
        )
        signed_sig_props = etree.SubElement(signed_properties, '{%s}SignedSignatureProperties' % NS_XADES)

        signing_time_elem = etree.SubElement(signed_sig_props, '{%s}SigningTime' % NS_XADES)
        signing_time_elem.text = signing_time

        signing_cert = etree.SubElement(signed_sig_props, '{%s}SigningCertificate' % NS_XADES)
        cert_elem = etree.SubElement(signing_cert, '{%s}Cert' % NS_XADES)
        cert_digest_elem = etree.SubElement(cert_elem, '{%s}CertDigest' % NS_XADES)
        etree.SubElement(cert_digest_elem, '{%s}DigestMethod' % NS_DS, Algorithm='http://www.w3.org/2001/04/xmlenc#sha256')
        cert_digest_val = etree.SubElement(cert_digest_elem, '{%s}DigestValue' % NS_DS)
        cert_digest_val.text = cert_digest

        issuer_serial = etree.SubElement(cert_elem, '{%s}IssuerSerial' % NS_XADES)
        x509_issuer = etree.SubElement(issuer_serial, '{%s}X509IssuerName' % NS_DS)
        x509_issuer.text = cert.issuer.rfc4514_string()
        x509_serial = etree.SubElement(issuer_serial, '{%s}X509SerialNumber' % NS_DS)
        x509_serial.text = str(cert.serial_number)

        # Add Signature to document
        doc.append(signature)

        # Calculate SignedProperties hash
        signed_props_c14n = etree.tostring(signed_properties, method='c14n', exclusive=True)
        signed_props_digest = base64.b64encode(hashlib.sha256(signed_props_c14n).digest()).decode()
        digest_val2.text = signed_props_digest

        # Calculate document hash (with enveloped-signature transform)
        doc.remove(signature)
        doc_c14n = etree.tostring(doc, method='c14n', exclusive=True)
        doc_digest = base64.b64encode(hashlib.sha256(doc_c14n).digest()).decode()
        digest_val1.text = doc_digest
        doc.append(signature)

        # Calculate SignedInfo signature
        signed_info_c14n = etree.tostring(signed_info, method='c14n', exclusive=True)

        if isinstance(private_key, rsa_keys.RSAPrivateKey):
            signature_value = private_key.sign(signed_info_c14n, padding.PKCS1v15(), hashes.SHA256())
            sig_value.text = base64.b64encode(signature_value).decode()
        else:
            der_signature = private_key.sign(signed_info_c14n, ec.ECDSA(hashes.SHA256()))
            raw_signature = self._der_to_raw_ecdsa(der_signature, private_key.key_size)
            sig_value.text = base64.b64encode(raw_signature).decode()

        return '<?xml version="1.0" encoding="utf-8"?>' + etree.tostring(doc, encoding='unicode')

    def get_authorisation_challenge(self, nip: str) -> dict:
        """Get authorization challenge from KSeF."""
        data = {
            "contextIdentifier": {
                "type": "onip",
                "identifier": nip
            }
        }

        return self._make_request(
            'POST',
            '/auth/challenge',
            data=data,
            with_session=False
        )

    def init_session_xades(self, nip: str) -> dict:
        """
        Initialize KSeF session using XAdES signature with certificate.

        Flow:
        1. Get challenge from /auth/challenge
        2. Build and sign XML AuthTokenRequest
        3. Send to /auth/xades-signature
        4. Check authorization status
        5. Exchange for accessToken

        Args:
            nip: Entity NIP

        Returns:
            dict with access_token, refresh_token and reference_number
        """
        # Step 1: Get challenge
        logger.info(f"Getting challenge for NIP: {nip}")
        challenge_response = self.get_authorisation_challenge(nip)
        challenge = challenge_response.get('challenge')
        timestamp = challenge_response.get('timestamp')

        if not challenge:
            raise KSeFError(
                message="No challenge received from KSeF",
                response_data=challenge_response
            )

        logger.info(f"Received challenge: {challenge[:20]}...")

        # Step 2: Build and sign XML
        logger.info("Building and signing AuthTokenRequest XML...")
        xml_content = self._build_auth_token_request_xml(challenge, nip, timestamp)
        signed_xml = self._sign_xml_xades(xml_content)

        # Step 3: Send signed XML to /auth/xades-signature
        logger.info("Sending signed XML to /auth/xades-signature...")
        response = self._make_request(
            'POST',
            '/auth/xades-signature',
            xml_data=signed_xml,
            with_session=False
        )

        self.authentication_token = response.get('authenticationToken', {}).get('token')
        self.reference_number = response.get('referenceNumber')

        if not self.authentication_token:
            raise KSeFError(
                message="No authenticationToken received from KSeF",
                response_data=response
            )

        logger.info(f"Received authenticationToken, referenceNumber: {self.reference_number}")

        # Step 4: Check authorization status (polling)
        logger.info("Checking authorization status...")
        max_attempts = 30
        for attempt in range(max_attempts):
            status_response = self.check_auth_status()

            status_obj = status_response.get('status', {})
            processing_code = status_obj.get('code') or status_response.get('processingCode')

            if processing_code == 200:
                logger.info("Authorization completed successfully")
                break
            elif processing_code == 100:
                logger.info(f"Authorization in progress (attempt {attempt + 1}/{max_attempts})...")
                time.sleep(1)
            else:
                raise KSeFError(
                    message=f"Authorization error: code {processing_code}",
                    response_data=status_response
                )
        else:
            raise KSeFError(message="Authorization timeout")

        # Step 5: Exchange for accessToken
        logger.info("Exchanging authenticationToken for accessToken...")
        self.redeem_access_token()

        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'reference_number': self.reference_number,
        }

    def check_auth_status(self) -> dict:
        """Check authorization status."""
        if not self.reference_number:
            raise KSeFError("No reference_number")

        return self._make_request(
            'GET',
            f'/auth/{self.reference_number}',
            with_session=True
        )

    def redeem_access_token(self) -> dict:
        """
        Exchange authenticationToken for accessToken.

        WARNING: Can only be called once per authenticationToken!
        """
        response = self._make_request(
            'POST',
            '/auth/token/redeem',
            with_session=True
        )

        access_token_data = response.get('accessToken')
        refresh_token_data = response.get('refreshToken')

        if isinstance(access_token_data, dict):
            self.access_token = access_token_data.get('token')
        else:
            self.access_token = access_token_data

        if isinstance(refresh_token_data, dict):
            self.refresh_token = refresh_token_data.get('token')
        else:
            self.refresh_token = refresh_token_data

        return response

    def terminate_session(self) -> dict:
        """Terminate active KSeF session."""
        if not self.access_token:
            raise KSeFError("No active session to terminate")

        response = self._make_request(
            'DELETE',
            '/auth/sessions/current',
            with_session=True
        )

        self.authentication_token = None
        self.access_token = None
        self.refresh_token = None
        self.reference_number = None

        return response

    def query_invoices(
        self,
        subject_type: str = 'Subject2',
        date_from: datetime.date = None,
        date_to: datetime.date = None,
        date_type: str = 'Invoicing',
        page_size: int = 100,
        page_offset: int = 0
    ) -> dict:
        """
        Search invoices in KSeF.

        Args:
            subject_type: Subject type:
                - 'Subject1': issued invoices (sales)
                - 'Subject2': received invoices (purchases)
            date_from: Start date
            date_to: End date
            date_type: Date type ('Issue' or 'Invoicing')
            page_size: Results per page (max 250)
            page_offset: Page offset

        Returns:
            dict with invoice metadata list
        """
        if not self.access_token:
            raise KSeFError("No active session")

        if date_to is None:
            date_to = datetime.date.today()
        if date_from is None:
            date_from = date_to - datetime.timedelta(days=30)

        # KSeF limits date range to 90 days
        max_range = datetime.timedelta(days=90)
        if (date_to - date_from) > max_range:
            logger.warning(f"Date range exceeds 90 days, limiting to {date_to - max_range} - {date_to}")
            date_from = date_to - max_range

        data = {
            "subjectType": subject_type,
            "dateRange": {
                "dateType": date_type,
                "from": f"{date_from.isoformat()}T00:00:00",
                "to": f"{date_to.isoformat()}T23:59:59"
            }
        }

        query_params = f"?pageSize={min(page_size, 250)}&pageOffset={page_offset}"
        endpoint = f"/invoices/query/metadata{query_params}"

        return self._make_request('POST', endpoint, data=data, with_session=True)

    def get_invoice_xml(self, ksef_number: str) -> str:
        """
        Download invoice XML from KSeF.

        Args:
            ksef_number: KSeF invoice number

        Returns:
            Invoice XML as string
        """
        if not self.access_token:
            raise KSeFError("No active session")

        url = f"{self.base_url}/invoices/ksef/{ksef_number}"
        headers = self._get_headers(with_session=True)
        headers['Accept'] = 'application/octet-stream'

        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code >= 400:
            raise KSeFError(
                message=f"Error downloading invoice XML: {response.status_code}",
                status_code=response.status_code
            )

        return response.text


def format_amount(amount) -> str:
    """Format amount for display."""
    if amount is None:
        return "N/A"
    try:
        return f"{float(amount):,.2f}"
    except (ValueError, TypeError):
        return str(amount)


def print_invoices_table(invoices: list):
    """Print invoices as formatted table."""
    if not invoices:
        print("No invoices found.")
        return

    # Header
    print("\n" + "=" * 120)
    print(f"{'KSeF Number':<45} {'Invoice #':<20} {'Date':<12} {'Seller NIP':<12} {'Gross Amount':>15}")
    print("=" * 120)

    for inv in invoices:
        ksef_num = inv.get('ksefNumber', 'N/A')[:44]
        inv_num = inv.get('invoiceNumber', 'N/A')[:19]
        inv_date = inv.get('issueDate', 'N/A')[:11]

        seller = inv.get('seller', {})
        seller_nip = seller.get('nip', 'N/A') if isinstance(seller, dict) else 'N/A'

        gross = format_amount(inv.get('grossAmount'))

        print(f"{ksef_num:<45} {inv_num:<20} {inv_date:<12} {seller_nip:<12} {gross:>15}")

    print("=" * 120)
    print(f"Total: {len(invoices)} invoice(s)")


def print_invoices_json(invoices: list):
    """Print invoices as JSON."""
    print(json.dumps(invoices, indent=2, ensure_ascii=False, default=str))


def main():
    parser = argparse.ArgumentParser(
        description='Fetch invoices from KSeF (Krajowy System e-Faktur)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --nip 1234567890 --cert cert.pem --key key.pem --password secret
    %(prog)s --nip 1234567890 --cert cert.pem --key key.pem --password-file pass.txt
    %(prog)s --nip 1234567890 --cert cert.pem --key key.pem --env prod --date-from 2025-01-01
    %(prog)s --nip 1234567890 --cert cert.pem --key key.pem --subject-type Subject1 --output json
        """
    )

    parser.add_argument('--nip', required=True, help='NIP of the entity')
    parser.add_argument('--cert', required=True, help='Path to certificate file (PEM)')
    parser.add_argument('--key', required=True, help='Path to private key file (PEM)')
    parser.add_argument('--password', help='Password for encrypted private key')
    parser.add_argument('--password-file', help='File containing password for private key')
    parser.add_argument('--env', choices=['test', 'demo', 'prod'], default='prod',
                        help='KSeF environment (default: prod)')
    parser.add_argument('--date-from', help='Start date YYYY-MM-DD (default: 30 days ago)')
    parser.add_argument('--date-to', help='End date YYYY-MM-DD (default: today)')
    parser.add_argument('--subject-type', choices=['Subject1', 'Subject2'], default='Subject2',
                        help='Subject1=issued/sales, Subject2=received/purchases (default: Subject2)')
    parser.add_argument('--output', choices=['table', 'json'], default='table',
                        help='Output format (default: table)')
    parser.add_argument('--download-xml', action='store_true',
                        help='Download full XML for each invoice')
    parser.add_argument('--xml-output-dir', default='.',
                        help='Directory to save XML files (default: current directory)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Get password
    password = args.password
    if not password and args.password_file:
        if not os.path.exists(args.password_file):
            print(f"Error: Password file not found: {args.password_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.password_file, 'r') as f:
            password = f.read().strip()

    # Validate files
    if not os.path.exists(args.cert):
        print(f"Error: Certificate file not found: {args.cert}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.key):
        print(f"Error: Private key file not found: {args.key}", file=sys.stderr)
        sys.exit(1)

    # Parse dates
    date_from = None
    date_to = None
    if args.date_from:
        try:
            date_from = datetime.datetime.strptime(args.date_from, '%Y-%m-%d').date()
        except ValueError:
            print(f"Error: Invalid date format for --date-from: {args.date_from}", file=sys.stderr)
            sys.exit(1)
    if args.date_to:
        try:
            date_to = datetime.datetime.strptime(args.date_to, '%Y-%m-%d').date()
        except ValueError:
            print(f"Error: Invalid date format for --date-to: {args.date_to}", file=sys.stderr)
            sys.exit(1)

    try:
        # Create client
        client = KSeFClient(
            cert_path=args.cert,
            key_path=args.key,
            key_password=password,
            environment=args.env
        )

        print(f"Connecting to KSeF ({args.env} environment)...")
        print(f"NIP: {args.nip}")

        # Initialize session
        session_info = client.init_session_xades(args.nip)
        print(f"Session initialized. Reference: {session_info['reference_number']}")

        # Query invoices
        print(f"\nQuerying {args.subject_type} invoices...")
        if date_from:
            print(f"Date range: {date_from} to {date_to or 'today'}")

        result = client.query_invoices(
            subject_type=args.subject_type,
            date_from=date_from,
            date_to=date_to
        )

        invoices = result.get('invoices', [])

        # Output results
        if args.output == 'json':
            print_invoices_json(invoices)
        else:
            print_invoices_table(invoices)

        # Download XML if requested
        if args.download_xml and invoices:
            print(f"\nDownloading XML files to: {args.xml_output_dir}")
            os.makedirs(args.xml_output_dir, exist_ok=True)

            for inv in invoices:
                ksef_number = inv.get('ksefNumber')
                if ksef_number:
                    try:
                        xml_content = client.get_invoice_xml(ksef_number)
                        # Sanitize filename
                        safe_name = ksef_number.replace('/', '_').replace('\\', '_')
                        filepath = os.path.join(args.xml_output_dir, f"{safe_name}.xml")
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(xml_content)
                        print(f"  Downloaded: {filepath}")
                    except KSeFError as e:
                        print(f"  Error downloading {ksef_number}: {e.message}", file=sys.stderr)

        # Terminate session
        print("\nTerminating session...")
        client.terminate_session()
        print("Session terminated.")

    except KSeFError as e:
        print(f"\nKSeF Error: {e.message}", file=sys.stderr)
        if e.response_data:
            print(f"Details: {json.dumps(e.response_data, indent=2)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
