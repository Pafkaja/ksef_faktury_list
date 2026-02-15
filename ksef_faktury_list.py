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
This script supports two authentication methods:
- XAdES-BES digital signature with a qualified certificate
- KSeF authorization token

Usage:
    # Certificate authentication (XAdES)
    python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password secret
    python ksef_faktury_list.py --nip 1234567890 --cert cert.pem --key key.pem --password-file haslo.txt

    # Token authentication
    python ksef_faktury_list.py --nip 1234567890 --token "your-ksef-token"
    python ksef_faktury_list.py --nip 1234567890 --token-file token.txt

Options:
    --nip           NIP of the entity (required)
    --cert          Path to certificate file (PEM format) - for XAdES auth
    --key           Path to private key file (PEM format) - for XAdES auth
    --password      Password for encrypted private key
    --password-file File containing password for private key
    --token         KSeF authorization token - for token auth
    --token-file    File containing KSeF token
    --env           Environment: test, demo, prod (default: prod)
    --date-from     Start date YYYY-MM-DD (default: 30 days ago)
    --date-to       End date YYYY-MM-DD (default: today)
    --subject-type  Subject1 (issued/sales) or Subject2 (received/purchases), default: Subject2
    --output        Output format: table, json, xml (default: table)
    --download-xml  Download full XML for each invoice
    --download-pdf  Generate PDF for each invoice
    --verbose       Enable verbose logging
"""

import argparse
import base64
import datetime
import hashlib
import io
import json
import logging
import os
import smtplib
import sys
import tempfile
import time
import uuid
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import requests
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.backends import default_backend

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

import qrcode

# Register DejaVu Sans font for Polish characters support
_FONT_REGISTERED = False
_FONT_NAME = 'Helvetica'  # fallback

def _register_polish_font():
    """Register font with Polish characters support."""
    global _FONT_REGISTERED, _FONT_NAME
    if _FONT_REGISTERED:
        return

    # Common paths for DejaVu fonts
    font_paths = [
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf',
        '/usr/share/fonts/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/TTF/DejaVuSans.ttf',
        'C:/Windows/Fonts/DejaVuSans.ttf',
    ]

    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont('DejaVuSans', font_path))
                _FONT_NAME = 'DejaVuSans'
                logger.info(f"Registered font: {font_path}")
                break
            except Exception as e:
                logger.warning(f"Failed to register font {font_path}: {e}")

    _FONT_REGISTERED = True

# KSeF API URLs
KSEF_URLS = {
    'test': 'https://api-test.ksef.mf.gov.pl/v2',
    'demo': 'https://api-demo.ksef.mf.gov.pl/v2',
    'prod': 'https://api.ksef.mf.gov.pl/v2',
}

# KSeF QR verification URLs (per environment)
KSEF_QR_URLS = {
    'test': 'https://qr-test.ksef.mf.gov.pl',
    'demo': 'https://qr-demo.ksef.mf.gov.pl',
    'prod': 'https://qr.ksef.mf.gov.pl',
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
    Standalone KSeF API client with XAdES or token authentication.
    """

    def __init__(
        self,
        cert_path: str = None,
        key_path: str = None,
        key_password: str = None,
        token: str = None,
        environment: str = 'test',
        timeout: int = 30
    ):
        """
        Initialize KSeF client.

        Args:
            cert_path: Path to X.509 certificate (PEM format) - for XAdES auth
            key_path: Path to private key (PEM format) - for XAdES auth
            key_password: Password for encrypted private key
            token: KSeF authorization token - for token auth
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
        self._ksef_token = token

        # Session tokens
        self.authentication_token = None
        self.access_token = None
        self.refresh_token = None
        self.reference_number = None

        # Loaded certificate and key (lazy loading)
        self._certificate = None
        self._private_key = None
        self._public_key_pem = None

    @classmethod
    def from_token(cls, token: str, environment: str = 'test', timeout: int = 30):
        """
        Create KSeF client for token-based authentication.

        Args:
            token: KSeF authorization token
            environment: API environment ('test', 'demo', 'prod')
            timeout: Request timeout in seconds

        Returns:
            KSeFClient instance configured for token auth
        """
        return cls(token=token, environment=environment, timeout=timeout)

    @classmethod
    def from_certificate(cls, cert_path: str, key_path: str, key_password: str = None,
                         environment: str = 'test', timeout: int = 30):
        """
        Create KSeF client for certificate-based (XAdES) authentication.

        Args:
            cert_path: Path to X.509 certificate (PEM format)
            key_path: Path to private key (PEM format)
            key_password: Password for encrypted private key
            environment: API environment ('test', 'demo', 'prod')
            timeout: Request timeout in seconds

        Returns:
            KSeFClient instance configured for XAdES auth
        """
        return cls(cert_path=cert_path, key_path=key_path, key_password=key_password,
                   environment=environment, timeout=timeout)

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

    def get_public_key(self) -> str:
        """
        Get public key certificate for token encryption from KSeF.

        Returns:
            PEM-encoded public key
        """
        if self._public_key_pem:
            return self._public_key_pem

        response = self._make_request(
            'GET',
            '/security/public-key-certificates',
            with_session=False
        )

        # Response can be list or dict with 'certificates' key
        if isinstance(response, list):
            certificates = response
        else:
            certificates = response.get('certificates', [])

        if not certificates:
            raise KSeFError("No public key certificates available from KSeF")

        # Find active certificate
        cert_pem = None
        for cert in certificates:
            status = cert.get('status', '')
            if status.lower() == 'active' or not status:
                cert_pem = cert.get('certificate') or cert.get('publicKey')
                if cert_pem:
                    break

        if not cert_pem:
            # Fallback to first certificate
            cert_pem = certificates[0].get('certificate') or certificates[0].get('publicKey')

        if not cert_pem:
            raise KSeFError("Could not extract public key from KSeF response", response_data=response)

        # Ensure proper PEM format
        if not cert_pem.startswith('-----'):
            cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_pem}\n-----END CERTIFICATE-----"

        self._public_key_pem = cert_pem
        return cert_pem

    def _encrypt_token_for_ksef(self, token: str, timestamp_ms: int) -> str:
        """
        Encrypt token with KSeF public key using RSA-OAEP.

        Args:
            token: KSeF authorization token
            timestamp_ms: Timestamp in milliseconds (from challenge)

        Returns:
            Base64-encoded encrypted token
        """
        # Format: token|timestamp
        token_with_timestamp = f"{token}|{timestamp_ms}"

        # Get public key
        public_key_pem = self.get_public_key()

        # Load public key (can be certificate or raw public key)
        try:
            # Try loading as certificate first
            if '-----BEGIN CERTIFICATE-----' in public_key_pem:
                cert = x509.load_pem_x509_certificate(public_key_pem.encode(), default_backend())
                public_key = cert.public_key()
            else:
                # Try as raw public key
                public_key = serialization.load_pem_public_key(public_key_pem.encode(), default_backend())
        except Exception as e:
            raise KSeFError(f"Failed to load public key: {e}")

        # Encrypt using RSA-OAEP with SHA-256
        encrypted = public_key.encrypt(
            token_with_timestamp.encode('utf-8'),
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted).decode('utf-8')

    def init_session_token(self, nip: str) -> dict:
        """
        Initialize KSeF session using authorization token.

        Flow:
        1. Get challenge from /auth/challenge
        2. Encrypt token with public key (RSA-OAEP)
        3. Send to /auth/token
        4. Check authorization status
        5. Exchange for accessToken

        Args:
            nip: Entity NIP

        Returns:
            dict with access_token, refresh_token and reference_number
        """
        if not self._ksef_token:
            raise KSeFError("No KSeF token configured. Use from_token() or provide token parameter.")

        # Step 1: Get challenge
        logger.info(f"Getting challenge for NIP: {nip}")
        challenge_response = self.get_authorisation_challenge(nip)
        challenge = challenge_response.get('challenge')
        timestamp_ms = challenge_response.get('timestampMs')

        if not challenge or timestamp_ms is None:
            raise KSeFError(
                message="No challenge or timestamp received from KSeF",
                response_data=challenge_response
            )

        logger.info(f"Received challenge: {challenge[:20]}..., timestamp: {timestamp_ms}")

        # Step 2: Encrypt token
        logger.info("Encrypting token with KSeF public key...")
        encrypted_token = self._encrypt_token_for_ksef(self._ksef_token, timestamp_ms)

        # Step 3: Send encrypted token to /auth/ksef-token
        logger.info("Sending encrypted token to /auth/ksef-token...")
        data = {
            "challenge": challenge,
            "contextIdentifier": {
                "type": "Nip",
                "value": nip
            },
            "encryptedToken": encrypted_token
        }

        response = self._make_request(
            'POST',
            '/auth/ksef-token',
            data=data,
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
                description = status_obj.get('description', 'Unknown error')
                details = status_obj.get('details', [])
                raise KSeFError(
                    message=f"Authorization error: code {processing_code} - {description}. {' '.join(details or [])}",
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


class InvoicePDFGenerator:
    """Generate PDF from KSeF invoice XML."""

    # KSeF XML namespaces
    NAMESPACES = {
        'fa': 'http://crd.gov.pl/wzor/2025/06/25/13775/',
        'etd': 'http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2022/01/05/eD/DefinicjeTypy/',
    }

    def __init__(self):
        _register_polish_font()
        self.font_name = _FONT_NAME
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Setup custom paragraph styles with Polish font."""
        # Update base styles to use Polish font
        for style_name in ['Normal', 'Heading1', 'Heading2', 'Heading3', 'BodyText']:
            if style_name in self.styles:
                self.styles[style_name].fontName = self.font_name

        self.styles.add(ParagraphStyle(
            name='InvoiceTitle',
            fontName=self.font_name,
            fontSize=16,
            leading=20,
            alignment=1,  # center
            spaceAfter=10,
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            fontName=self.font_name,
            fontSize=11,
            leading=14,
            spaceBefore=10,
            spaceAfter=5,
            textColor=colors.HexColor('#333333'),
        ))
        self.styles.add(ParagraphStyle(
            name='CompanyName',
            fontName=self.font_name,
            fontSize=10,
            leading=12,
        ))
        self.styles.add(ParagraphStyle(
            name='CompanyDetails',
            fontName=self.font_name,
            fontSize=9,
            leading=11,
            textColor=colors.HexColor('#555555'),
        ))
        self.styles.add(ParagraphStyle(
            name='Footer',
            fontName=self.font_name,
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#666666'),
        ))

    def _get_text(self, element, xpath: str, default: str = '') -> str:
        """Extract text from XML element using xpath."""
        # Try with namespace prefix
        for prefix, ns in self.NAMESPACES.items():
            try:
                result = element.find(xpath.replace('//', f'//{prefix}:').replace('/', f'/{prefix}:'),
                                      {prefix: ns})
                if result is not None and result.text:
                    return result.text.strip()
            except Exception:
                pass

        # Try without namespace (some XMLs don't use prefixes)
        try:
            # Remove namespace from element for search
            for elem in element.iter():
                if '}' in elem.tag:
                    elem.tag = elem.tag.split('}')[1]
            result = element.find(xpath.lstrip('/'))
            if result is not None and result.text:
                return result.text.strip()
        except Exception:
            pass

        return default

    def _parse_xml(self, xml_content: str) -> dict:
        """Parse KSeF XML invoice into dictionary."""
        # Remove namespace prefixes for easier parsing
        xml_clean = xml_content
        root = etree.fromstring(xml_clean.encode('utf-8'))

        # Strip namespaces from tags for easier access
        for elem in root.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}')[1]

        data = {
            'invoice_number': '',
            'invoice_date': '',
            'currency': 'PLN',
            'seller': {},
            'buyer': {},
            'items': [],
            'summary': {},
            'payment': {},
            'additional_descriptions': [],
            'pricing_type': 'net',
            'footer': [],
        }

        # Invoice number and date
        fa = root.find('.//Fa')
        if fa is not None:
            data['invoice_number'] = fa.findtext('P_2', '')
            data['invoice_date'] = fa.findtext('P_1', '')
            data['currency'] = fa.findtext('KodWaluty', 'PLN')

            # Period
            okres = fa.find('OkresFa')
            if okres is not None:
                data['period_from'] = okres.findtext('P_6_Od', '')
                data['period_to'] = okres.findtext('P_6_Do', '')

            # Summary totals - collect all VAT rates
            vat_rate_fields = [
                ('P_13_1', 'P_14_1', 'P_14_1W', '23%'),
                ('P_13_2', 'P_14_2', 'P_14_2W', '22%'),
                ('P_13_3', 'P_14_3', 'P_14_3W', '8%'),
                ('P_13_4', 'P_14_4', 'P_14_4W', '7%'),
                ('P_13_5', 'P_14_5', 'P_14_5W', '5%'),
                ('P_13_6_1', None, None, '0%'),
                ('P_13_6_2', None, None, '0% (WDT)'),
                ('P_13_6_3', None, None, '0% (eksport)'),
                ('P_13_7', None, None, 'zw'),
                ('P_13_8', None, None, 'np'),
            ]
            rates = []
            for net_field, vat_field, vat_conv_field, label in vat_rate_fields:
                net = self._parse_amount(fa.findtext(net_field, ''))
                vat = self._parse_amount(fa.findtext(vat_field, '')) if vat_field else 0.0
                vat_conv = self._parse_amount(fa.findtext(vat_conv_field, '')) if vat_conv_field else 0.0
                if net:
                    rates.append({'label': label, 'net': net, 'vat': vat, 'vat_converted': vat_conv})
            data['summary'] = {
                'rates': rates,
                'gross': self._parse_amount(fa.findtext('P_15', '0')),
            }

            # Items
            for wiersz in fa.findall('FaWiersz'):
                item = {
                    'lp': wiersz.findtext('NrWierszaFa', ''),
                    'name': wiersz.findtext('P_7', ''),
                    'unit': wiersz.findtext('P_8A', ''),
                    'qty': self._parse_amount(wiersz.findtext('P_8B', '1')),
                    'unit_price_net': self._parse_amount(wiersz.findtext('P_9A', '')),
                    'unit_price_gross': self._parse_amount(wiersz.findtext('P_9B', '')),
                    'net_value': self._parse_amount(wiersz.findtext('P_11', '')),
                    'gross_value': self._parse_amount(wiersz.findtext('P_11A', '')),
                    'vat_rate': wiersz.findtext('P_12', ''),
                    'vat_value': self._parse_amount(wiersz.findtext('P_11Vat', '')),
                }
                data['items'].append(item)

            # Determine pricing type (net vs gross)
            has_net_prices = any(item['unit_price_net'] for item in data['items'])
            data['pricing_type'] = 'net' if has_net_prices else 'gross'

            # Additional descriptions (DodatkowyOpis)
            for opis in fa.findall('DodatkowyOpis'):
                klucz = opis.findtext('Klucz', '')
                wartosc = opis.findtext('Wartosc', '')
                if klucz or wartosc:
                    data['additional_descriptions'].append({'key': klucz, 'value': wartosc})

            # Payment info
            platnosc = fa.find('Platnosc')
            if platnosc is not None:
                data['payment']['description'] = platnosc.findtext('OpisPlatnosci', '')
                data['payment']['form'] = platnosc.findtext('FormaPlatnosci', '')
                # Due dates (can be multiple TerminPlatnosci entries)
                terminy = platnosc.findall('TerminPlatnosci')
                due_dates = []
                for termin in terminy:
                    date = termin.findtext('Termin', '') or (termin.text.strip() if termin.text else '')
                    if date:
                        due_dates.append(date)
                data['payment']['due_dates'] = due_dates
                # Bank account
                rachunek = platnosc.find('RachunekBankowy')
                if rachunek is not None:
                    data['payment']['bank_account'] = rachunek.findtext('NrRB', '')
                    data['payment']['bank_name'] = rachunek.findtext('NazwaBanku', '')

        # Seller (Podmiot1)
        podmiot1 = root.find('.//Podmiot1')
        if podmiot1 is not None:
            dane = podmiot1.find('DaneIdentyfikacyjne')
            adres = podmiot1.find('Adres')
            data['seller'] = {
                'nip': dane.findtext('NIP', '') if dane is not None else '',
                'name': dane.findtext('Nazwa', '') if dane is not None else '',
                'address1': adres.findtext('AdresL1', '') if adres is not None else '',
                'address2': adres.findtext('AdresL2', '') if adres is not None else '',
                'country': adres.findtext('KodKraju', 'PL') if adres is not None else 'PL',
            }

        # Buyer (Podmiot2)
        podmiot2 = root.find('.//Podmiot2')
        if podmiot2 is not None:
            dane = podmiot2.find('DaneIdentyfikacyjne')
            adres = podmiot2.find('Adres')
            data['buyer'] = {
                'nip': dane.findtext('NIP', '') if dane is not None else '',
                'name': dane.findtext('Nazwa', '') if dane is not None else '',
                'address1': adres.findtext('AdresL1', '') if adres is not None else '',
                'address2': adres.findtext('AdresL2', '') if adres is not None else '',
                'country': adres.findtext('KodKraju', 'PL') if adres is not None else 'PL',
            }

        # Footer
        stopka = root.find('.//Stopka')
        if stopka is not None:
            for info in stopka.findall('.//StopkaFaktury'):
                if info.text:
                    data['footer'].append(info.text.strip())
            rejestry = stopka.find('Rejestry')
            if rejestry is not None:
                krs = rejestry.findtext('KRS', '')
                regon = rejestry.findtext('REGON', '')
                if krs:
                    data['footer'].append(f'KRS: {krs}')
                if regon:
                    data['footer'].append(f'REGON: {regon}')

        return data

    def _parse_amount(self, value: str) -> float:
        """Parse amount string to float."""
        if not value:
            return 0.0
        try:
            return float(value.replace(',', '.').replace(' ', ''))
        except ValueError:
            return 0.0

    def _format_amount(self, amount: float, currency: str = 'PLN') -> str:
        """Format amount for display."""
        return f"{amount:,.2f} {currency}".replace(',', ' ').replace('.', ',').replace(' ', ' ')

    def _generate_qr_image(self, xml_content: str, seller_nip: str,
                           invoice_date: str, environment: str = 'prod') -> io.BytesIO:
        """
        Generate QR code image for KSeF invoice verification.

        The QR encodes a verification URL per the KSeF specification:
        {base_url}/invoice/{seller_nip}/{DD-MM-YYYY}/{SHA256_base64url}

        Args:
            xml_content: Original invoice XML content (used for SHA-256 hash)
            seller_nip: Seller's NIP number
            invoice_date: Invoice date in YYYY-MM-DD format (from P_1)
            environment: KSeF environment ('test', 'demo', 'prod')

        Returns:
            BytesIO buffer containing QR code PNG image
        """
        # SHA-256 hash of XML content, Base64URL encoded
        xml_bytes = xml_content.encode('utf-8')
        sha256_hash = hashlib.sha256(xml_bytes).digest()
        hash_b64url = base64.urlsafe_b64encode(sha256_hash).rstrip(b'=').decode('ascii')

        # Convert date from YYYY-MM-DD to DD-MM-YYYY
        try:
            dt = datetime.datetime.strptime(invoice_date, '%Y-%m-%d')
            date_formatted = dt.strftime('%d-%m-%Y')
        except (ValueError, TypeError):
            date_formatted = invoice_date

        base_url = KSEF_QR_URLS.get(environment, KSEF_QR_URLS['prod'])
        verification_url = f"{base_url}/invoice/{seller_nip}/{date_formatted}/{hash_b64url}"

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=4,
            border=2,
        )
        qr.add_data(verification_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return buf

    def generate_pdf(self, xml_content: str, output_path: str,
                     environment: str = 'prod', ksef_number: str = None) -> str:
        """
        Generate PDF from KSeF XML invoice.

        Args:
            xml_content: Invoice XML content
            output_path: Path to save PDF file
            environment: KSeF environment for QR code URL ('test', 'demo', 'prod')
            ksef_number: KSeF reference number (displayed below QR code)

        Returns:
            Path to generated PDF
        """
        data = self._parse_xml(xml_content)
        currency = data.get('currency', 'PLN')

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=15*mm,
            leftMargin=15*mm,
            topMargin=15*mm,
            bottomMargin=15*mm
        )

        elements = []

        # Title
        title = Paragraph(f"FAKTURA VAT nr {data['invoice_number']}", self.styles['InvoiceTitle'])
        elements.append(title)

        # KSeF number (if available)
        if ksef_number:
            elements.append(Paragraph(f"Numer KSeF: {ksef_number}", self.styles['Normal']))

        # Invoice date and period
        date_text = f"Data wystawienia: {data['invoice_date']}"
        if data.get('period_from') and data.get('period_to'):
            date_text += f"<br/>Okres rozliczeniowy: {data['period_from']} - {data['period_to']}"
        elements.append(Paragraph(date_text, self.styles['Normal']))
        elements.append(Spacer(1, 10*mm))

        # Seller and Buyer side by side
        seller = data.get('seller', {})
        buyer = data.get('buyer', {})

        parties_data = [
            [
                Paragraph("<b>SPRZEDAWCA</b>", self.styles['SectionHeader']),
                Paragraph("<b>NABYWCA</b>", self.styles['SectionHeader'])
            ],
            [
                Paragraph(f"<b>{seller.get('name', '')}</b>", self.styles['CompanyName']),
                Paragraph(f"<b>{buyer.get('name', '')}</b>", self.styles['CompanyName'])
            ],
            [
                Paragraph(f"NIP: {seller.get('nip', '')}", self.styles['CompanyDetails']),
                Paragraph(f"NIP: {buyer.get('nip', '')}", self.styles['CompanyDetails'])
            ],
            [
                Paragraph(seller.get('address1', ''), self.styles['CompanyDetails']),
                Paragraph(buyer.get('address1', ''), self.styles['CompanyDetails'])
            ],
            [
                Paragraph(seller.get('address2', ''), self.styles['CompanyDetails']),
                Paragraph(buyer.get('address2', ''), self.styles['CompanyDetails'])
            ],
        ]

        parties_table = Table(parties_data, colWidths=[90*mm, 90*mm])
        parties_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(parties_table)
        elements.append(Spacer(1, 8*mm))

        # Items table
        elements.append(Paragraph("<b>POZYCJE FAKTURY</b>", self.styles['SectionHeader']))

        # Table header - adjust labels based on pricing type
        pricing_type = data.get('pricing_type', 'net')
        if pricing_type == 'net':
            price_label = 'Cena netto'
            value_label = 'Wartość netto'
        else:
            price_label = 'Cena brutto'
            value_label = 'Wartość brutto'

        items_header = ['Lp.', 'Nazwa towaru/usługi', 'J.m.', 'Ilość', price_label, value_label, 'VAT']
        items_data = [items_header]

        for item in data.get('items', []):
            if pricing_type == 'net':
                unit_price = item.get('unit_price_net') or item.get('unit_price_gross', 0)
                value = item.get('net_value') or item.get('gross_value', 0)
            else:
                unit_price = item.get('unit_price_gross') or item.get('unit_price_net', 0)
                value = item.get('gross_value') or item.get('net_value', 0)

            vat_rate = item.get('vat_rate', '')
            if vat_rate and vat_rate not in ('zw', 'np', 'oo'):
                vat_display = f"{vat_rate}%"
            else:
                vat_display = vat_rate

            row = [
                item['lp'],
                Paragraph(item['name'], self.styles['Normal']),
                item['unit'],
                f"{item['qty']:.2f}".replace('.', ','),
                self._format_amount(unit_price, ''),
                self._format_amount(value, ''),
                vat_display,
            ]
            items_data.append(row)

        col_widths = [10*mm, 70*mm, 15*mm, 15*mm, 25*mm, 25*mm, 15*mm]
        items_table = Table(items_data, colWidths=col_widths)
        items_table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), self.font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Lp
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),  # J.m.
            ('ALIGN', (3, 1), (-1, -1), 'RIGHT'),  # Numbers
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F2F2F2')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(items_table)
        elements.append(Spacer(1, 8*mm))

        # Summary
        elements.append(Paragraph("<b>PODSUMOWANIE</b>", self.styles['SectionHeader']))

        summary = data.get('summary', {})
        summary_data = []

        for rate in summary.get('rates', []):
            summary_data.append([
                f"Wartość netto ({rate['label']}):",
                self._format_amount(rate['net'], currency)
            ])
            if rate.get('vat'):
                summary_data.append([
                    f"VAT ({rate['label']}):",
                    self._format_amount(rate['vat'], currency)
                ])
            if rate.get('vat_converted'):
                summary_data.append([
                    f"VAT ({rate['label']}) w PLN:",
                    self._format_amount(rate['vat_converted'], 'PLN')
                ])

        summary_data.append(['', ''])
        summary_data.append([
            '<b>RAZEM DO ZAPŁATY:</b>',
            f"<b>{self._format_amount(summary.get('gross', 0), currency)}</b>"
        ])

        summary_table_data = [[Paragraph(str(row[0]), self.styles['Normal']),
                               Paragraph(str(row[1]), self.styles['Normal'])] for row in summary_data]

        summary_table = Table(summary_table_data, colWidths=[120*mm, 55*mm])
        summary_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(summary_table)

        # Payment info
        payment = data.get('payment', {})
        if any(payment.values()):
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph("<b>PŁATNOŚĆ</b>", self.styles['SectionHeader']))

            payment_form_names = {
                '1': 'gotówka', '2': 'karta', '3': 'bon', '4': 'czek',
                '5': 'kredyt', '6': 'przelew', '7': 'mobilna',
            }
            if payment.get('form'):
                form_display = payment_form_names.get(payment['form'], payment['form'])
                elements.append(Paragraph(f"Forma płatności: {form_display}", self.styles['Normal']))
            if payment.get('due_dates'):
                for date in payment['due_dates']:
                    elements.append(Paragraph(f"Termin płatności: {date}", self.styles['Normal']))
            if payment.get('bank_account'):
                line = f"Nr rachunku: {payment['bank_account']}"
                if payment.get('bank_name'):
                    line += f" ({payment['bank_name']})"
                elements.append(Paragraph(line, self.styles['Normal']))
            if payment.get('description'):
                elements.append(Paragraph(f"{payment['description']}", self.styles['Normal']))

        # Additional descriptions (DodatkowyOpis)
        additional_descs = data.get('additional_descriptions', [])
        if additional_descs:
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph("<b>INFORMACJE DODATKOWE</b>", self.styles['SectionHeader']))
            for desc in additional_descs:
                key = desc.get('key', '')
                value = desc.get('value', '')
                if key and value:
                    elements.append(Paragraph(f"<b>{key}:</b> {value}", self.styles['Normal']))
                elif value:
                    elements.append(Paragraph(value, self.styles['Normal']))

        # Footer
        if data.get('footer'):
            elements.append(Spacer(1, 10*mm))
            elements.append(Paragraph("<b>Informacje dodatkowe:</b>", self.styles['Footer']))
            for line in data['footer']:
                elements.append(Paragraph(line, self.styles['Footer']))

        # KSeF QR code and note
        elements.append(Spacer(1, 5*mm))

        seller_nip = data.get('seller', {}).get('nip', '')
        invoice_date = data.get('invoice_date', '')
        if seller_nip and invoice_date:
            try:
                qr_buf = self._generate_qr_image(xml_content, seller_nip, invoice_date, environment)
                qr_img = Image(qr_buf, width=30*mm, height=30*mm)

                ksef_label = ksef_number if ksef_number else ''
                qr_table_data = [[
                    qr_img,
                    [
                        Paragraph(
                            "Faktura wygenerowana z Krajowego Systemu e-Faktur (KSeF)",
                            self.styles['Footer']
                        ),
                        Spacer(1, 2*mm),
                        Paragraph(
                            "Kod QR służy do weryfikacji faktury w systemie KSeF",
                            self.styles['Footer']
                        ),
                    ] + ([
                        Spacer(1, 2*mm),
                        Paragraph(f"Numer KSeF: {ksef_label}", self.styles['Footer']),
                    ] if ksef_label else []),
                ]]
                qr_table = Table(qr_table_data, colWidths=[35*mm, 140*mm])
                qr_table.setStyle(TableStyle([
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (0, 0), 0),
                    ('LEFTPADDING', (1, 0), (1, 0), 5*mm),
                ]))
                elements.append(qr_table)
            except Exception as e:
                logger.warning(f"Nie udało się wygenerować kodu QR: {e}")
                elements.append(Paragraph(
                    "Faktura wygenerowana z Krajowego Systemu e-Faktur (KSeF)",
                    self.styles['Footer']
                ))
        else:
            elements.append(Paragraph(
                "Faktura wygenerowana z Krajowego Systemu e-Faktur (KSeF)",
                self.styles['Footer']
            ))

        doc.build(elements)
        return output_path


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
        print("Nie znaleziono faktur.")
        return

    # Nagłówek
    print("\n" + "=" * 120)
    print(f"{'Numer KSeF':<45} {'Nr faktury':<20} {'Data':<12} {'NIP sprzed.':<12} {'Kwota brutto':>15}")
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
    print(f"Razem: {len(invoices)} faktur(a/y)")


def print_invoices_json(invoices: list):
    """Print invoices as JSON."""
    print(json.dumps(invoices, indent=2, ensure_ascii=False, default=str))


def send_invoice_email(
    smtp_host, smtp_port, smtp_user, smtp_password,
    email_from, email_to, subject,
    invoice_number, ksef_number,
    xml_content=None, pdf_path=None
):
    """
    Send invoice email with PDF and XML attachments.

    Args:
        smtp_host: SMTP server address
        smtp_port: SMTP server port
        smtp_user: SMTP username
        smtp_password: SMTP password
        email_from: Sender email address
        email_to: List of recipient email addresses
        subject: Email subject
        invoice_number: Invoice number (for email body)
        ksef_number: KSeF number (for email body and attachment filenames)
        xml_content: Invoice XML content string (optional)
        pdf_path: Path to invoice PDF file (optional)
    """
    logger.info(f"Przygotowywanie emaila dla faktury {invoice_number} (KSeF: {ksef_number})")
    logger.debug(f"  Od: {email_from}, Do: {', '.join(email_to)}")
    logger.debug(f"  Temat: {subject}")

    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = ', '.join(email_to)
    msg['Subject'] = subject

    body = f"Faktura nr: {invoice_number}\nNumer KSeF: {ksef_number}\n"
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    safe_name = ksef_number.replace('/', '_').replace('\\', '_')

    if pdf_path and os.path.exists(pdf_path):
        with open(pdf_path, 'rb') as f:
            pdf_data = f.read()
        pdf_attachment = MIMEApplication(pdf_data, _subtype='pdf')
        pdf_attachment.add_header('Content-Disposition', 'attachment', filename=f"{safe_name}.pdf")
        msg.attach(pdf_attachment)
        logger.info(f"  Dołączono PDF: {safe_name}.pdf ({len(pdf_data)} bajtów)")
    else:
        logger.warning(f"  Brak załącznika PDF (ścieżka: {pdf_path})")

    if xml_content:
        xml_bytes = xml_content.encode('utf-8')
        xml_attachment = MIMEApplication(xml_bytes, _subtype='xml')
        xml_attachment.add_header('Content-Disposition', 'attachment', filename=f"{safe_name}.xml")
        msg.attach(xml_attachment)
        logger.info(f"  Dołączono XML: {safe_name}.xml ({len(xml_bytes)} bajtów)")
    else:
        logger.warning(f"  Brak załącznika XML")

    logger.info(f"Łączenie z SMTP {smtp_host}:{smtp_port}...")
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.set_debuglevel(logger.isEnabledFor(logging.DEBUG))
        logger.debug("  STARTTLS...")
        server.starttls()
        logger.debug(f"  Logowanie jako {smtp_user}...")
        server.login(smtp_user, smtp_password)
        server.sendmail(email_from, email_to, msg.as_string())
        logger.info(f"Email wysłany pomyślnie dla {ksef_number}")


def send_grouped_email(
    smtp_host, smtp_port, smtp_user, smtp_password,
    email_from, email_to, subject,
    invoices_data
):
    """
    Send a single email with all invoices as attachments.

    Args:
        smtp_host: SMTP server address
        smtp_port: SMTP server port
        smtp_user: SMTP username
        smtp_password: SMTP password
        email_from: Sender email address
        email_to: List of recipient email addresses
        subject: Email subject
        invoices_data: List of dicts with keys: invoice_number, ksef_number, xml_content, pdf_path
    """
    logger.info(f"Przygotowywanie zbiorczego emaila z {len(invoices_data)} fakturą/ami")
    logger.debug(f"  Od: {email_from}, Do: {', '.join(email_to)}")
    logger.debug(f"  Temat: {subject}")

    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = ', '.join(email_to)
    msg['Subject'] = subject

    body_lines = [f"Faktury KSeF ({len(invoices_data)} szt.):\n"]
    for inv in invoices_data:
        body_lines.append(f"  - {inv['invoice_number']} (KSeF: {inv['ksef_number']})")
    msg.attach(MIMEText('\n'.join(body_lines), 'plain', 'utf-8'))

    attachment_count = 0
    for inv in invoices_data:
        safe_name = inv['ksef_number'].replace('/', '_').replace('\\', '_')

        if inv.get('pdf_path') and os.path.exists(inv['pdf_path']):
            with open(inv['pdf_path'], 'rb') as f:
                pdf_data = f.read()
            pdf_attachment = MIMEApplication(pdf_data, _subtype='pdf')
            pdf_attachment.add_header('Content-Disposition', 'attachment', filename=f"{safe_name}.pdf")
            msg.attach(pdf_attachment)
            attachment_count += 1
            logger.info(f"  Dołączono PDF: {safe_name}.pdf ({len(pdf_data)} bajtów)")

        if inv.get('xml_content'):
            xml_bytes = inv['xml_content'].encode('utf-8')
            xml_attachment = MIMEApplication(xml_bytes, _subtype='xml')
            xml_attachment.add_header('Content-Disposition', 'attachment', filename=f"{safe_name}.xml")
            msg.attach(xml_attachment)
            attachment_count += 1
            logger.info(f"  Dołączono XML: {safe_name}.xml ({len(xml_bytes)} bajtów)")

    logger.info(f"Łączna liczba załączników: {attachment_count}")
    logger.info(f"Łączenie z SMTP {smtp_host}:{smtp_port}...")
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.set_debuglevel(logger.isEnabledFor(logging.DEBUG))
        logger.debug("  STARTTLS...")
        server.starttls()
        logger.debug(f"  Logowanie jako {smtp_user}...")
        server.login(smtp_user, smtp_password)
        server.sendmail(email_from, email_to, msg.as_string())
        logger.info(f"Email zbiorczy wysłany pomyślnie ({len(invoices_data)} faktur, {attachment_count} załączników)")


def main():
    parser = argparse.ArgumentParser(
        description='Fetch invoices from KSeF (Krajowy System e-Faktur)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Certificate authentication (XAdES)
    %(prog)s --nip 1234567890 --cert cert.pem --key key.pem --password secret
    %(prog)s --nip 1234567890 --cert cert.pem --key key.pem --password-file pass.txt

    # Token authentication
    %(prog)s --nip 1234567890 --token "your-ksef-token"
    %(prog)s --nip 1234567890 --token-file token.txt

    # With options
    %(prog)s --nip 1234567890 --token-file token.txt --env prod --date-from 2025-01-01
    %(prog)s --nip 1234567890 --token-file token.txt --download-pdf --pdf-output-dir ./pdf

    # Offline XML to PDF conversion (no authentication needed)
    %(prog)s --xml-to-pdf faktura.xml
    %(prog)s --xml-to-pdf ./faktury_xml/ --pdf-output-dir ./faktury_pdf/
        """
    )

    parser.add_argument('--nip', help='NIP of the entity (required for KSeF queries)')

    # Offline XML to PDF conversion
    offline_group = parser.add_argument_group('Offline XML to PDF conversion (no authentication needed)')
    offline_group.add_argument('--xml-to-pdf', metavar='PATH',
                               help='Convert XML file or directory of XML files to PDF (offline, no KSeF auth)')

    # Certificate auth options
    auth_cert = parser.add_argument_group('Certificate authentication (XAdES)')
    auth_cert.add_argument('--cert', help='Path to certificate file (PEM)')
    auth_cert.add_argument('--key', help='Path to private key file (PEM)')
    auth_cert.add_argument('--password', help='Password for encrypted private key')
    auth_cert.add_argument('--password-file', help='File containing password for private key')

    # Token auth options
    auth_token = parser.add_argument_group('Token authentication')
    auth_token.add_argument('--token', help='KSeF authorization token')
    auth_token.add_argument('--token-file', help='File containing KSeF token')
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
    parser.add_argument('--download-pdf', action='store_true',
                        help='Generate PDF for each invoice')
    parser.add_argument('--pdf-output-dir', default='.',
                        help='Directory to save PDF files (default: current directory)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')

    # Email options
    email_group = parser.add_argument_group('Email sending')
    email_group.add_argument('--send-email', action='store_true',
                             help='Send invoices by email')
    email_group.add_argument('--smtp-host', help='SMTP server address')
    email_group.add_argument('--smtp-port', type=int, default=587,
                             help='SMTP server port (default: 587)')
    email_group.add_argument('--smtp-user', help='SMTP username')
    email_group.add_argument('--smtp-password', help='SMTP password')
    email_group.add_argument('--smtp-password-file', help='File containing SMTP password')
    email_group.add_argument('--email-from', help='Sender email address')
    email_group.add_argument('--email-to', action='append', metavar='ADDRESS',
                             help='Recipient email address (can be specified multiple times)')
    email_group.add_argument('--email-subject',
                             default='Faktura KSeF: {invoice_number}',
                             help='Email subject template (default: "Faktura KSeF: {invoice_number}")')
    email_group.add_argument('--email-group', choices=['single', 'all'], default='single',
                             help='Grouping: single (one email per invoice, default) or all (all in one email)')

    args = parser.parse_args()

    # Auto-enable --send-email when SMTP options are provided
    if args.smtp_host and not args.send_email:
        args.send_email = True

    # Default --email-from to --smtp-user if not specified
    if not args.email_from and args.smtp_user:
        args.email_from = args.smtp_user

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Offline XML to PDF conversion (no authentication needed)
    if args.xml_to_pdf:
        xml_path = args.xml_to_pdf
        pdf_output_dir = args.pdf_output_dir

        if not os.path.exists(xml_path):
            print(f"Błąd: Ścieżka nie znaleziona: {xml_path}", file=sys.stderr)
            sys.exit(1)

        # Collect XML files
        if os.path.isfile(xml_path):
            xml_files = [xml_path]
        else:
            xml_files = sorted(
                f.path for f in os.scandir(xml_path)
                if f.is_file() and f.name.lower().endswith('.xml')
            )
            if not xml_files:
                print(f"Błąd: Nie znaleziono plików XML w: {xml_path}", file=sys.stderr)
                sys.exit(1)

        os.makedirs(pdf_output_dir, exist_ok=True)
        pdf_generator = InvoicePDFGenerator()

        print(f"Konwersja {len(xml_files)} plików XML na PDF...")
        ok_count = 0
        err_count = 0
        for xml_file in xml_files:
            try:
                with open(xml_file, 'r', encoding='utf-8') as f:
                    xml_content = f.read()

                base_name = os.path.splitext(os.path.basename(xml_file))[0]
                pdf_path = os.path.join(pdf_output_dir, f"{base_name}.pdf")
                pdf_generator.generate_pdf(xml_content, pdf_path,
                                           environment=args.env, ksef_number=base_name)
                print(f"  OK: {xml_file} -> {pdf_path}")
                ok_count += 1
            except Exception as e:
                print(f"  Błąd: {xml_file}: {e}", file=sys.stderr)
                err_count += 1

        print(f"\nGotowe. Skonwertowano: {ok_count}, błędy: {err_count}")
        sys.exit(0 if err_count == 0 else 1)

    # Determine authentication method
    use_token_auth = args.token or args.token_file
    use_cert_auth = args.cert or args.key

    if not args.nip:
        print("Błąd: --nip jest wymagany dla zapytań KSeF", file=sys.stderr)
        sys.exit(1)

    if not use_token_auth and not use_cert_auth:
        print("Błąd: Wymagane jest podanie tokenu (--token/--token-file) lub certyfikatu (--cert/--key)", file=sys.stderr)
        sys.exit(1)

    if use_token_auth and use_cert_auth:
        print("Błąd: Nie można używać jednocześnie tokenu i certyfikatu. Wybierz jedną metodę.", file=sys.stderr)
        sys.exit(1)

    # Get token
    token = None
    if use_token_auth:
        token = args.token
        if not token and args.token_file:
            if not os.path.exists(args.token_file):
                print(f"Błąd: Plik tokenu nie znaleziony: {args.token_file}", file=sys.stderr)
                sys.exit(1)
            with open(args.token_file, 'r') as f:
                token = f.read().strip()
        if not token:
            print("Błąd: Token jest pusty", file=sys.stderr)
            sys.exit(1)

    # Get password for certificate
    password = None
    if use_cert_auth:
        password = args.password
        if not password and args.password_file:
            if not os.path.exists(args.password_file):
                print(f"Błąd: Plik hasła nie znaleziony: {args.password_file}", file=sys.stderr)
                sys.exit(1)
            with open(args.password_file, 'r') as f:
                password = f.read().strip()

        # Validate certificate files
        if not args.cert or not os.path.exists(args.cert):
            print(f"Błąd: Plik certyfikatu nie znaleziony: {args.cert}", file=sys.stderr)
            sys.exit(1)
        if not args.key or not os.path.exists(args.key):
            print(f"Błąd: Plik klucza prywatnego nie znaleziony: {args.key}", file=sys.stderr)
            sys.exit(1)

    # Parse dates
    date_from = None
    date_to = None
    if args.date_from:
        try:
            date_from = datetime.datetime.strptime(args.date_from, '%Y-%m-%d').date()
        except ValueError:
            print(f"Błąd: Nieprawidłowy format daty --date-from: {args.date_from}", file=sys.stderr)
            sys.exit(1)
    if args.date_to:
        try:
            date_to = datetime.datetime.strptime(args.date_to, '%Y-%m-%d').date()
        except ValueError:
            print(f"Błąd: Nieprawidłowy format daty --date-to: {args.date_to}", file=sys.stderr)
            sys.exit(1)

    try:
        # Create client based on authentication method
        if use_token_auth:
            client = KSeFClient.from_token(
                token=token,
                environment=args.env
            )
            auth_method = "token"
        else:
            client = KSeFClient.from_certificate(
                cert_path=args.cert,
                key_path=args.key,
                key_password=password,
                environment=args.env
            )
            auth_method = "certyfikat (XAdES)"

        print(f"Łączenie z KSeF (środowisko: {args.env})...")
        print(f"NIP: {args.nip}")
        print(f"Metoda autoryzacji: {auth_method}")

        # Initialize session
        if use_token_auth:
            session_info = client.init_session_token(args.nip)
        else:
            session_info = client.init_session_xades(args.nip)
        print(f"Sesja zainicjalizowana. Numer referencyjny: {session_info['reference_number']}")

        # Query invoices
        subject_type_label = "wystawione (sprzedaż)" if args.subject_type == "Subject1" else "otrzymane (zakupy)"
        print(f"\nPobieranie faktur {subject_type_label}...")
        if date_from:
            print(f"Zakres dat: {date_from} - {date_to or 'dziś'}")

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

        # Caches to avoid duplicate KSeF API calls across download-xml, download-pdf, and send-email
        xml_cache = {}   # ksef_number -> xml_content
        pdf_cache = {}   # ksef_number -> pdf_path

        def get_xml_cached(ksef_number):
            if ksef_number not in xml_cache:
                xml_cache[ksef_number] = client.get_invoice_xml(ksef_number)
            return xml_cache[ksef_number]

        # Download XML if requested
        if args.download_xml and invoices:
            print(f"\nPobieranie plików XML do: {args.xml_output_dir}")
            os.makedirs(args.xml_output_dir, exist_ok=True)

            for inv in invoices:
                ksef_number = inv.get('ksefNumber')
                if ksef_number:
                    try:
                        xml_content = get_xml_cached(ksef_number)
                        # Sanitize filename
                        safe_name = ksef_number.replace('/', '_').replace('\\', '_')
                        filepath = os.path.join(args.xml_output_dir, f"{safe_name}.xml")
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(xml_content)
                        print(f"  Pobrano: {filepath}")
                    except KSeFError as e:
                        print(f"  Błąd pobierania {ksef_number}: {e.message}", file=sys.stderr)

        # Generate PDF if requested
        if args.download_pdf and invoices:
            print(f"\nGenerowanie plików PDF do: {args.pdf_output_dir}")
            os.makedirs(args.pdf_output_dir, exist_ok=True)
            pdf_generator = InvoicePDFGenerator()

            for inv in invoices:
                ksef_number = inv.get('ksefNumber')
                if ksef_number:
                    try:
                        xml_content = get_xml_cached(ksef_number)
                        # Sanitize filename
                        safe_name = ksef_number.replace('/', '_').replace('\\', '_')
                        filepath = os.path.join(args.pdf_output_dir, f"{safe_name}.pdf")
                        pdf_generator.generate_pdf(xml_content, filepath,
                                                   environment=args.env, ksef_number=ksef_number)
                        pdf_cache[ksef_number] = filepath
                        print(f"  Wygenerowano: {filepath}")
                    except KSeFError as e:
                        print(f"  Błąd generowania PDF dla {ksef_number}: {e.message}", file=sys.stderr)
                    except Exception as e:
                        print(f"  Błąd generowania PDF dla {ksef_number}: {e}", file=sys.stderr)

        # Send invoices by email if requested
        if args.send_email and invoices:
            # Validate required SMTP arguments
            missing = []
            if not args.smtp_host:
                missing.append('--smtp-host')
            if not args.smtp_user:
                missing.append('--smtp-user')
            if not args.email_from:
                missing.append('--email-from')
            if not args.email_to:
                missing.append('--email-to')

            smtp_password = args.smtp_password
            if not smtp_password and args.smtp_password_file:
                if not os.path.exists(args.smtp_password_file):
                    print(f"Błąd: Plik hasła SMTP nie znaleziony: {args.smtp_password_file}", file=sys.stderr)
                    sys.exit(1)
                with open(args.smtp_password_file, 'r') as f:
                    smtp_password = f.read().strip()
            if not smtp_password:
                missing.append('--smtp-password or --smtp-password-file')

            if missing:
                print(f"Błąd: Brakujące wymagane opcje email: {', '.join(missing)}", file=sys.stderr)
                sys.exit(1)

            pdf_generator_email = InvoicePDFGenerator()
            temp_pdfs = []

            logger.info(f"Konfiguracja email: host={args.smtp_host}:{args.smtp_port}, "
                         f"użytkownik={args.smtp_user}, od={args.email_from}, "
                         f"do={args.email_to}, grupowanie={args.email_group}")
            logger.info(f"Szablon tematu: {args.email_subject}")
            logger.info(f"Liczba faktur do wysłania: {len(invoices)}")

            try:
                print(f"\nWysyłanie faktur emailem (tryb: {args.email_group})...")

                if args.email_group == 'all':
                    # Collect all invoice data, then send one email
                    invoices_data = []
                    for inv in invoices:
                        ksef_number = inv.get('ksefNumber')
                        invoice_number = inv.get('invoiceNumber', ksef_number or 'N/A')
                        if not ksef_number:
                            logger.warning(f"Pomijanie faktury bez numeru KSeF: {inv}")
                            continue
                        try:
                            xml_content = get_xml_cached(ksef_number)
                            logger.info(f"  Pobrano XML dla {ksef_number} ({len(xml_content)} bajtów)")
                        except KSeFError as e:
                            print(f"  Błąd pobierania XML dla {ksef_number}: {e.message}", file=sys.stderr)
                            continue

                        pdf_path = pdf_cache.get(ksef_number)
                        if pdf_path:
                            logger.info(f"  PDF z cache dla {ksef_number}: {pdf_path}")
                        else:
                            try:
                                tmp = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
                                tmp.close()
                                pdf_generator_email.generate_pdf(xml_content, tmp.name,
                                                                 environment=args.env, ksef_number=ksef_number)
                                pdf_path = tmp.name
                                pdf_cache[ksef_number] = pdf_path
                                temp_pdfs.append(tmp.name)
                                logger.info(f"  Wygenerowano tymczasowy PDF dla {ksef_number}: {tmp.name}")
                            except Exception as e:
                                print(f"  Błąd generowania PDF dla {ksef_number}: {e}", file=sys.stderr)
                                logger.error(f"  Błąd generowania PDF dla {ksef_number}: {e}")
                                pdf_path = None

                        invoices_data.append({
                            'invoice_number': invoice_number,
                            'ksef_number': ksef_number,
                            'xml_content': xml_content,
                            'pdf_path': pdf_path,
                        })

                    if invoices_data:
                        subject = args.email_subject.format(
                            invoice_number=f"{len(invoices_data)} faktur"
                        )
                        logger.info(f"Wysyłanie zbiorczego emaila z {len(invoices_data)} fakturą/ami...")
                        send_grouped_email(
                            smtp_host=args.smtp_host,
                            smtp_port=args.smtp_port,
                            smtp_user=args.smtp_user,
                            smtp_password=smtp_password,
                            email_from=args.email_from,
                            email_to=args.email_to,
                            subject=subject,
                            invoices_data=invoices_data,
                        )
                        print(f"  Wysłano 1 email z {len(invoices_data)} fakturą/ami")
                    else:
                        logger.warning("Brak faktur do wysłania w trybie zbiorczym")
                else:
                    # Send one email per invoice
                    sent_count = 0
                    err_count = 0
                    for idx, inv in enumerate(invoices, 1):
                        ksef_number = inv.get('ksefNumber')
                        invoice_number = inv.get('invoiceNumber', ksef_number or 'N/A')
                        if not ksef_number:
                            logger.warning(f"Pomijanie faktury bez numeru KSeF: {inv}")
                            continue

                        logger.info(f"Przetwarzanie faktury {idx}/{len(invoices)}: {invoice_number} ({ksef_number})")

                        try:
                            xml_content = get_xml_cached(ksef_number)
                            logger.info(f"  Pobrano XML dla {ksef_number} ({len(xml_content)} bajtów)")
                        except KSeFError as e:
                            print(f"  Błąd pobierania XML dla {ksef_number}: {e.message}", file=sys.stderr)
                            err_count += 1
                            continue

                        pdf_path = pdf_cache.get(ksef_number)
                        if pdf_path:
                            logger.info(f"  PDF z cache dla {ksef_number}: {pdf_path}")
                        else:
                            try:
                                tmp = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
                                tmp.close()
                                pdf_generator_email.generate_pdf(xml_content, tmp.name,
                                                                 environment=args.env, ksef_number=ksef_number)
                                pdf_path = tmp.name
                                pdf_cache[ksef_number] = pdf_path
                                temp_pdfs.append(tmp.name)
                                logger.info(f"  Wygenerowano tymczasowy PDF dla {ksef_number}: {tmp.name}")
                            except Exception as e:
                                print(f"  Błąd generowania PDF dla {ksef_number}: {e}", file=sys.stderr)
                                logger.error(f"  Błąd generowania PDF dla {ksef_number}: {e}")
                                pdf_path = None

                        subject = args.email_subject.format(invoice_number=invoice_number)
                        try:
                            send_invoice_email(
                                smtp_host=args.smtp_host,
                                smtp_port=args.smtp_port,
                                smtp_user=args.smtp_user,
                                smtp_password=smtp_password,
                                email_from=args.email_from,
                                email_to=args.email_to,
                                subject=subject,
                                invoice_number=invoice_number,
                                ksef_number=ksef_number,
                                xml_content=xml_content,
                                pdf_path=pdf_path,
                            )
                            sent_count += 1
                            print(f"  Wysłano: {invoice_number} ({ksef_number})")
                        except Exception as e:
                            err_count += 1
                            print(f"  Błąd wysyłania emaila dla {ksef_number}: {e}", file=sys.stderr)
                            logger.error(f"  Błąd SMTP dla {ksef_number}: {e}")

                    print(f"  Wysłano {sent_count} email(i)" + (f", błędy: {err_count}" if err_count else ""))

            finally:
                # Clean up temporary PDFs
                if temp_pdfs:
                    logger.info(f"Usuwanie {len(temp_pdfs)} tymczasowych plików PDF")
                for tmp_path in temp_pdfs:
                    try:
                        os.unlink(tmp_path)
                        logger.debug(f"  Usunięto plik tymczasowy: {tmp_path}")
                    except OSError as e:
                        logger.warning(f"  Nie udało się usunąć pliku tymczasowego {tmp_path}: {e}")

        # Terminate session
        print("\nKończenie sesji...")
        client.terminate_session()
        print("Sesja zakończona.")

    except KSeFError as e:
        print(f"\nBłąd KSeF: {e.message}", file=sys.stderr)
        if e.response_data:
            print(f"Szczegóły: {json.dumps(e.response_data, indent=2)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nNieoczekiwany błąd: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
