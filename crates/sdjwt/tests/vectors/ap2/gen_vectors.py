#!/usr/bin/env python3
"""Generate AP2 v0.2 interop test vectors with the AP2 Python SDK.

Usage:
    python gen_vectors.py --ap2-repo /path/to/AP2 --out ap2_vectors.json

Everything is generated with throwaway keys created on each run. Only PUBLIC
JWKs are written to the output. Re-running produces different bytes (ES256
signatures are randomized and keys are fresh); the committed file is one fixed
snapshot. Each vector records what the reference SDK itself said about it
(`sdk_result`) next to the `expected` outcome for a conforming implementation.
"""

import argparse
import copy
import json
import subprocess
import sys
import time

from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--ap2-repo', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    args = ap.parse_args()
    sys.path.insert(0, str(args.ap2_repo / 'code' / 'sdk' / 'python'))
    sdk_commit = subprocess.check_output(
        ['git', '-C', str(args.ap2_repo), 'rev-parse', 'HEAD'], text=True
    ).strip()

    from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
    from ap2.sdk.generated.checkout_mandate import CheckoutMandate
    from ap2.sdk.generated.open_checkout_mandate import (
        AllowedMerchants,
        OpenCheckoutMandate,
    )
    from ap2.sdk.generated.open_payment_mandate import (
        AllowedPayees,
        AmountRange,
        OpenPaymentMandate,
        PaymentReference,
    )
    from ap2.sdk.generated.payment_mandate import PaymentMandate
    from ap2.sdk.generated.types.amount import Amount
    from ap2.sdk.generated.types.checkout import Checkout, Status
    from ap2.sdk.generated.types.item import Item
    from ap2.sdk.generated.types.line_item import LineItem
    from ap2.sdk.generated.types.link import Link
    from ap2.sdk.generated.types.merchant import Merchant
    from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
    from ap2.sdk.generated.types.pisp import PISP
    from ap2.sdk.generated.types.total import Total
    from ap2.sdk.jwt_helper import create_jwt, verify_jwt
    from ap2.sdk.mandate import MandateClient
    from ap2.sdk.payment_mandate_chain import PaymentMandateChain
    from ap2.sdk.receipt_wrapper import ReceiptClient
    from ap2.sdk.utils import b64url_decode, b64url_encode, compute_sha256_b64url
    from cryptography.hazmat.primitives.asymmetric import ec
    from jwcrypto.jwk import JWK

    mc = MandateClient()
    rc = ReceiptClient()

    # ---- throwaway keys -------------------------------------------------
    def new_key(kid: str) -> JWK:
        k = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
        d = json.loads(k.export())
        d['kid'] = kid
        return JWK.from_json(json.dumps(d))

    def pub(k: JWK) -> JWK:
        return JWK.from_json(k.export_public())

    def pub_dict(k: JWK) -> dict:
        return json.loads(k.export_public())

    user = new_key('user-key-1')        # root issuer of open / human-present mandates
    agent = new_key('agent-key-1')      # delegate (cnf of open mandates)
    other = new_key('wrong-key-1')      # a key that is NOT the cnf key
    merchant_k = new_key('merchant-key-1')
    psp_k = new_key('psp-key-1')
    keys = {
        'user': pub_dict(user),
        'agent': pub_dict(agent),
        'wrong_key_not_in_cnf': pub_dict(other),
        'merchant': pub_dict(merchant_k),
        'payment_service_provider': pub_dict(psp_k),
    }

    def cnf(k: JWK) -> dict:
        return {'jwk': pub_dict(k)}

    now = int(time.time())
    AUD_M, NONCE_M = 'https://merchant.example', 'nonce-merchant-0001'

    # ---- merchant-signed checkout JWT ----------------------------------
    merchant = Merchant(id='merchant-1', name='Example Store')

    def make_checkout(price: int = 19900, qty: int = 1) -> str:
        item = Item(id='sku-1', title='Widget', price=price)
        li = LineItem(
            id='li-1', item=item, quantity=qty,
            totals=[Total(type='subtotal', amount=price * qty),
                    Total(type='total', amount=price * qty)],
        )
        co = Checkout(
            id='chk-0001', merchant=merchant, line_items=[li],
            status=Status.incomplete, currency='USD',
            totals=[Total(type='subtotal', amount=price * qty),
                    Total(type='total', amount=price * qty)],
            links=[Link(type='privacy_policy', url='https://merchant.example/privacy'),
                   Link(type='terms_of_service', url='https://merchant.example/tos')],
        )
        payload = json.loads(co.model_dump_json(exclude_none=True))
        return create_jwt({'alg': 'ES256', 'typ': 'JWT', 'kid': 'merchant-key-1'},
                          payload, merchant_k)

    checkout_jwt = make_checkout()
    checkout_hash = compute_sha256_b64url(checkout_jwt)

    # ---- helpers ---------------------------------------------------------
    def jwk_for_root(_t):
        return pub(user)

    def sdk_verify_chain(token, expected_aud=None, expected_nonce=None):
        try:
            payloads = mc.verify(token=token, key_or_provider=jwk_for_root,
                                 expected_aud=expected_aud,
                                 expected_nonce=expected_nonce)
            return {'ok': True, 'payloads': payloads}
        except Exception as e:  # noqa: BLE001
            return {'ok': False, 'error': f'{type(e).__name__}: {e}'}

    def sdk_verify_single(token, payload_type, key):
        try:
            m = mc.verify(token=token, key_or_provider=pub(key),
                          payload_type=payload_type)
            return {'ok': True, 'payload': json.loads(m.mandate_payload.model_dump_json(exclude_none=True))}
        except Exception as e:  # noqa: BLE001
            return {'ok': False, 'error': f'{type(e).__name__}: {e}'}

    def tamper_disclosure(seg_b64):
        """Re-encode a disclosure with a semantically altered value (digest must no longer match)."""
        arr = json.loads(b64url_decode(seg_b64))
        last = arr[-1]
        if isinstance(last, str):
            arr[-1] = last + 'x'
        elif isinstance(last, bool):
            arr[-1] = not last
        elif isinstance(last, (int, float)):
            arr[-1] = last + 1
        elif isinstance(last, dict):
            arr[-1] = dict(last, _tampered=True)
        elif isinstance(last, list):
            arr[-1] = last + ['tampered']
        else:
            arr[-1] = 'tampered'
        return b64url_encode(json.dumps(arr, separators=(',', ':')).encode())

    vectors = []

    def add(vid, kind, description, token, expected_valid, sdk_result, **extra):
        if sdk_result.get('ok') is not None and sdk_result['ok'] != expected_valid:
            extra['sdk_disagrees_with_expected'] = True
        sdk_result = {k: v for k, v in sdk_result.items() if k != 'payloads'} | (
            {'effective_payloads': sdk_result['payloads']} if 'payloads' in sdk_result else {})
        vectors.append({'id': vid, 'type': kind, 'description': description,
                        'token': token, 'expected_valid': expected_valid,
                        'sdk_result': sdk_result, **extra})

    # ---- HUMAN-NOT-PRESENT: open mandates --------------------------------
    open_co = OpenCheckoutMandate(
        constraints=[AllowedMerchants(allowed=[merchant])], cnf=cnf(agent),
        iat=now, exp=now + 3600)
    open_co_tok = mc.create(payloads=[open_co], issuer_key=user)
    add('open-checkout-valid', 'open_checkout_mandate',
        'Root SD-JWT issued by the user key; cnf = agent key.', open_co_tok, True,
        sdk_verify_single(open_co_tok, OpenCheckoutMandate, user),
        verify_with='user')
    add('open-checkout-wrong-issuer-key', 'open_checkout_mandate',
        'Same token, verified against a key that did not sign it.', open_co_tok, False,
        sdk_verify_single(open_co_tok, OpenCheckoutMandate, other),
        verify_with='wrong_key_not_in_cnf')
    # tampered disclosure: flip one char inside the first disclosure
    parts = open_co_tok.split('~')
    if len(parts) > 2:
        t_parts = list(parts)
        t_parts[1] = tamper_disclosure(parts[1])
        tampered = '~'.join(t_parts)
        add('open-checkout-tampered-disclosure', 'open_checkout_mandate',
            'First disclosure value altered and re-encoded; its digest no longer matches the signed JWT.',
            tampered, False, sdk_verify_single(tampered, OpenCheckoutMandate, user),
            verify_with='user')

    ref_digest = compute_sha256_b64url(open_co_tok.split('~', 1)[0])
    open_pay = OpenPaymentMandate(
        constraints=[AmountRange(currency='USD', max=50000, min=100),
                     AllowedPayees(allowed=[merchant]),
                     PaymentReference(conditional_transaction_id=ref_digest)],
        cnf=cnf(agent), iat=now, exp=now + 3600)
    open_pay_tok = mc.create(payloads=[open_pay], issuer_key=user)
    add('open-payment-valid', 'open_payment_mandate',
        'Root SD-JWT by user key; AmountRange(max=50000 minor units), AllowedPayees, '
        'PaymentReference(conditional_transaction_id = sha256 of the open checkout root JWT; '
        'see README "spec ambiguities").', open_pay_tok, True,
        sdk_verify_single(open_pay_tok, OpenPaymentMandate, user), verify_with='user')
    add('open-payment-wrong-issuer-key', 'open_payment_mandate',
        'Same token, verified against a key that did not sign it.', open_pay_tok, False,
        sdk_verify_single(open_pay_tok, OpenPaymentMandate, other), verify_with='wrong_key_not_in_cnf')
    pp = open_pay_tok.split('~')
    if len(pp) > 2:
        tp = list(pp)
        tp[1] = tamper_disclosure(pp[1])
        t = '~'.join(tp)
        add('open-payment-tampered-disclosure', 'open_payment_mandate',
            'First disclosure value altered and re-encoded.', t, False,
            sdk_verify_single(t, OpenPaymentMandate, user), verify_with='user')

    # ---- HNP: closed mandates (agent-signed hop on top of the open one) ----
    closed_co = CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=checkout_hash,
                                iat=now, exp=now + 600)
    co_chain = mc.present(holder_key=agent, mandate_token=open_co_tok,
                          payloads=[closed_co], aud=AUD_M, nonce=NONCE_M)
    r = sdk_verify_chain(co_chain, AUD_M, NONCE_M)
    c_viol = None
    if r['ok']:
        ch = CheckoutMandateChain.parse(r['payloads'])
        c_viol = ch.verify(expected_checkout_hash=checkout_hash, checkout_jwt=checkout_jwt)
        r['chain_constraint_violations'] = c_viol
    add('closed-checkout-hnp-valid', 'closed_checkout_mandate',
        'Human-not-present: open checkout (user) ~~ closed checkout (agent, terminal hop). '
        f'expected_aud={AUD_M}, expected_nonce={NONCE_M}.', co_chain, True,
        r, flow='human_not_present', verify_with='user (root), chain follows cnf',
        expected_aud=AUD_M, expected_nonce=NONCE_M, checkout_jwt=checkout_jwt,
        expected_checkout_hash=checkout_hash)

    # wrong cnf key: terminal hop signed by a key that is not the cnf key
    bad_cnf = mc.present(holder_key=other, mandate_token=open_co_tok,
                         payloads=[closed_co], aud=AUD_M, nonce=NONCE_M)
    add('closed-checkout-hnp-wrong-cnf-key', 'closed_checkout_mandate',
        'Terminal hop signed with a key that is not the cnf key of the open mandate.',
        bad_cnf, False, sdk_verify_chain(bad_cnf, AUD_M, NONCE_M),
        flow='human_not_present', expected_aud=AUD_M, expected_nonce=NONCE_M)

    # mismatched checkout_hash
    wrong_hash = compute_sha256_b64url(checkout_jwt + 'x')
    bad_hash_m = CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=wrong_hash,
                                 iat=now, exp=now + 600)
    bad_hash = mc.present(holder_key=agent, mandate_token=open_co_tok,
                          payloads=[bad_hash_m], aud=AUD_M, nonce=NONCE_M)
    r = sdk_verify_chain(bad_hash, AUD_M, NONCE_M)
    if r['ok']:
        ch = CheckoutMandateChain.parse(r['payloads'])
        v = ch.verify(expected_checkout_hash=checkout_hash, checkout_jwt=checkout_jwt)
        r['chain_constraint_violations'] = v
        # SDK-level signature chain is fine; the checkout_hash binding is what fails.
        r['ok'] = not v
    add('closed-checkout-hnp-mismatched-checkout-hash', 'closed_checkout_mandate',
        'Signature chain is valid but checkout_hash != base64url(sha256(checkout_jwt)).',
        bad_hash, False, r, flow='human_not_present', expected_aud=AUD_M,
        expected_nonce=NONCE_M, checkout_jwt=checkout_jwt,
        expected_checkout_hash=checkout_hash)

    # wrong audience / nonce
    add('closed-checkout-hnp-wrong-aud', 'closed_checkout_mandate',
        'Valid chain presented to a different audience than it was bound to.',
        co_chain, False, sdk_verify_chain(co_chain, 'https://other.example', NONCE_M),
        flow='human_not_present', expected_aud='https://other.example', expected_nonce=NONCE_M)

    # tampered disclosure in the presented chain
    ct = co_chain.split('~~')
    seg = ct[0].split('~')
    if len(seg) > 2:
        seg[1] = tamper_disclosure(seg[1])
        ct[0] = '~'.join(seg)
        t = '~~'.join(ct)
        add('closed-checkout-hnp-tampered-disclosure', 'closed_checkout_mandate',
            'A disclosure of the open (root) hop was altered after signing.', t, False,
            sdk_verify_chain(t, AUD_M, NONCE_M), flow='human_not_present',
            expected_aud=AUD_M, expected_nonce=NONCE_M)

    # closed payment (HNP)
    pisp = PISP(legal_name='Example Payments Ltd', brand_name='ExamplePay',
                domain_name='pay.example')
    closed_pay = PaymentMandate(
        transaction_id=checkout_hash, payee=merchant,
        payment_amount=Amount(amount=19900, currency='USD'),
        payment_instrument=PaymentInstrument(id='pi-1', type='card'),
        pisp=pisp, iat=now, exp=now + 600)
    AUD_P, NONCE_P = 'https://pay.example', 'nonce-psp-0001'
    pay_chain = mc.present(holder_key=agent, mandate_token=open_pay_tok,
                           payloads=[closed_pay], aud=AUD_P, nonce=NONCE_P)
    r = sdk_verify_chain(pay_chain, AUD_P, NONCE_P)
    if r['ok']:
        pc = PaymentMandateChain.parse(r['payloads'])
        r['chain_constraint_violations'] = pc.verify(
            expected_transaction_id=checkout_hash, expected_open_checkout_hash=ref_digest)
    add('closed-payment-hnp-valid', 'closed_payment_mandate',
        'Human-not-present: open payment (user) ~~ closed payment (agent). Amount 19900 minor units USD.',
        pay_chain, True, r, flow='human_not_present', expected_aud=AUD_P,
        expected_nonce=NONCE_P, expected_transaction_id=checkout_hash,
        expected_open_checkout_hash=ref_digest)
    bad_pay_cnf = mc.present(holder_key=other, mandate_token=open_pay_tok,
                             payloads=[closed_pay], aud=AUD_P, nonce=NONCE_P)
    add('closed-payment-hnp-wrong-cnf-key', 'closed_payment_mandate',
        'Terminal hop signed with a key that is not the cnf key.', bad_pay_cnf, False,
        sdk_verify_chain(bad_pay_cnf, AUD_P, NONCE_P), flow='human_not_present',
        expected_aud=AUD_P, expected_nonce=NONCE_P)
    over = PaymentMandate(
        transaction_id=checkout_hash, payee=merchant,
        payment_amount=Amount(amount=99999, currency='USD'),
        payment_instrument=PaymentInstrument(id='pi-1', type='card'), pisp=pisp,
        iat=now, exp=now + 600)
    over_chain = mc.present(holder_key=agent, mandate_token=open_pay_tok,
                            payloads=[over], aud=AUD_P, nonce=NONCE_P)
    r = sdk_verify_chain(over_chain, AUD_P, NONCE_P)
    if r['ok']:
        v = PaymentMandateChain.parse(r['payloads']).verify(
            expected_transaction_id=checkout_hash, expected_open_checkout_hash=ref_digest)
        r['chain_constraint_violations'] = v
        r['ok'] = not v
    add('closed-payment-hnp-amount-exceeds-constraint', 'closed_payment_mandate',
        'Signatures valid, but payment_amount 99999 > AmountRange.max 50000.',
        over_chain, False, r, flow='human_not_present', expected_aud=AUD_P,
        expected_nonce=NONCE_P, expected_transaction_id=checkout_hash,
        expected_open_checkout_hash=ref_digest)
    mism = PaymentMandate(
        transaction_id=compute_sha256_b64url('some other checkout'), payee=merchant,
        payment_amount=Amount(amount=19900, currency='USD'),
        payment_instrument=PaymentInstrument(id='pi-1', type='card'), pisp=pisp,
        iat=now, exp=now + 600)
    mism_chain = mc.present(holder_key=agent, mandate_token=open_pay_tok,
                            payloads=[mism], aud=AUD_P, nonce=NONCE_P)
    r = sdk_verify_chain(mism_chain, AUD_P, NONCE_P)
    if r['ok']:
        v = PaymentMandateChain.parse(r['payloads']).verify(
            expected_transaction_id=checkout_hash, expected_open_checkout_hash=ref_digest)
        r['chain_constraint_violations'] = v
        r['ok'] = not v
    add('closed-payment-hnp-mismatched-transaction-id', 'closed_payment_mandate',
        'Signatures valid, but transaction_id != checkout_hash of the checkout being paid.',
        mism_chain, False, r, flow='human_not_present', expected_aud=AUD_P,
        expected_nonce=NONCE_P, expected_transaction_id=checkout_hash,
        expected_open_checkout_hash=ref_digest)
    pt = pay_chain.split('~~')
    sg = pt[0].split('~')
    if len(sg) > 2:
        sg[1] = tamper_disclosure(sg[1])
        pt[0] = '~'.join(sg)
        t = '~~'.join(pt)
        add('closed-payment-hnp-tampered-disclosure', 'closed_payment_mandate',
            'A disclosure of the open (root) hop was altered.', t, False,
            sdk_verify_chain(t, AUD_P, NONCE_P), flow='human_not_present',
            expected_aud=AUD_P, expected_nonce=NONCE_P)

    # ---- HUMAN-PRESENT: closed mandates signed directly by the user --------
    hp_co_tok = mc.create(payloads=[closed_co], issuer_key=user)
    add('closed-checkout-hp-valid', 'closed_checkout_mandate',
        'Human-present: single root SD-JWT, closed checkout mandate signed directly by the user key.',
        hp_co_tok, True, sdk_verify_single(hp_co_tok, CheckoutMandate, user),
        flow='human_present', verify_with='user', checkout_jwt=checkout_jwt,
        expected_checkout_hash=checkout_hash)
    hp_bad = CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=wrong_hash,
                             iat=now, exp=now + 600)
    hp_bad_tok = mc.create(payloads=[hp_bad], issuer_key=user)
    add('closed-checkout-hp-mismatched-checkout-hash', 'closed_checkout_mandate',
        'Valid signature but checkout_hash != base64url(sha256(checkout_jwt)).',
        hp_bad_tok, False, {'ok': True, 'note': 'SDK single-token verify does not check the hash'},
        flow='human_present', verify_with='user', checkout_jwt=checkout_jwt,
        expected_checkout_hash=checkout_hash)
    hp_pay_tok = mc.create(payloads=[closed_pay], issuer_key=user)
    add('closed-payment-hp-valid', 'closed_payment_mandate',
        'Human-present: single root SD-JWT, closed payment mandate signed by the user key.',
        hp_pay_tok, True, sdk_verify_single(hp_pay_tok, PaymentMandate, user),
        flow='human_present', verify_with='user', expected_transaction_id=checkout_hash)
    add('closed-payment-hp-wrong-key', 'closed_payment_mandate',
        'Same token verified against a key that did not sign it.', hp_pay_tok, False,
        sdk_verify_single(hp_pay_tok, PaymentMandate, other), flow='human_present',
        verify_with='wrong_key_not_in_cnf')
    hp = hp_pay_tok.split('~')
    if len(hp) > 2:
        hp[1] = tamper_disclosure(hp[1])
        t = '~'.join(hp)
        add('closed-payment-hp-tampered-disclosure', 'closed_payment_mandate',
            'One disclosure altered.', t, False, sdk_verify_single(t, PaymentMandate, user),
            flow='human_present', verify_with='user')

    # ---- merchant checkout JWT -------------------------------------------
    def verify_checkout(tok, k):
        try:
            return {'ok': True, 'payload': verify_jwt(tok, pub(k))}
        except Exception as e:  # noqa: BLE001
            return {'ok': False, 'error': f'{type(e).__name__}: {e}'}

    add('merchant-checkout-jwt-valid', 'merchant_checkout_jwt',
        'ES256 JWS over the UCP Checkout object, signed by the merchant key.',
        checkout_jwt, True, verify_checkout(checkout_jwt, merchant_k), verify_with='merchant')
    h, p, s = checkout_jwt.split('.')
    pd = json.loads(b64url_decode(p))
    pd['currency'] = 'EUR'
    forged = '.'.join([h, b64url_encode(json.dumps(pd).encode()), s])
    add('merchant-checkout-jwt-tampered-payload', 'merchant_checkout_jwt',
        'Payload changed (currency USD->EUR) without re-signing.', forged, False,
        verify_checkout(forged, merchant_k), verify_with='merchant')
    add('merchant-checkout-jwt-wrong-key', 'merchant_checkout_jwt',
        'Verified against a key that did not sign it.', checkout_jwt, False,
        verify_checkout(checkout_jwt, other), verify_with='wrong_key_not_in_cnf')

    # ---- receipts ---------------------------------------------------------
    co_ref = compute_sha256_b64url(mc.get_closed_mandate_jwt(co_chain))
    pay_ref = compute_sha256_b64url(mc.get_closed_mandate_jwt(pay_chain))
    c_rcpt = json.loads(rc.create_checkout_receipt(
        merchant='merchant.example', reference=co_ref, order_id='order-0001').model_dump_json(exclude_none=True))
    p_rcpt = json.loads(rc.create_payment_receipt(closed_pay, pay_ref).model_dump_json(exclude_none=True))
    hdr = lambda kid: {'alg': 'ES256', 'typ': 'JWT', 'kid': kid}  # noqa: E731
    c_rcpt_jwt = create_jwt(hdr('merchant-key-1'), c_rcpt, merchant_k)
    p_rcpt_jwt = create_jwt(hdr('psp-key-1'), p_rcpt, psp_k)

    def _pyca_pub(k):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        return load_pem_public_key(pub(k).export_to_pem())

    def sdk_receipt(tok, k, is_payment, known_refs):
        cb = lambda ref: ref in known_refs  # noqa: E731
        out = {}
        try:
            # SDK type hint says ec.EllipticCurvePublicKey, but verify_jwt needs a JWK.
            out['documented_call_with_pyca_key'] = rc.verify_receipt(
                tok, _pyca_pub(k), has_reference_in_store_cb=cb, is_payment_receipt=is_payment)
        except Exception as e:  # noqa: BLE001
            out['documented_call_with_pyca_key'] = {'error': f'{type(e).__name__}: {e}'}
        try:
            out.update(rc.verify_receipt(
                tok, pub(k), has_reference_in_store_cb=cb, is_payment_receipt=is_payment))
        except Exception as e:  # noqa: BLE001
            out['error'] = f'{type(e).__name__}: {e}'
        return out

    def res(r):
        r = dict(r)
        r['ok'] = bool(r.get('verified'))
        return r

    add('checkout-receipt-valid', 'checkout_receipt',
        'Merchant-signed ES256 receipt; reference = base64url(sha256(closed checkout mandate JWT)).',
        c_rcpt_jwt, True, res(sdk_receipt(c_rcpt_jwt, merchant_k, False, {co_ref})),
        verify_with='merchant', known_references=[co_ref], payload=c_rcpt)
    add('checkout-receipt-wrong-key', 'checkout_receipt', 'Verified against the wrong key.',
        c_rcpt_jwt, False, res(sdk_receipt(c_rcpt_jwt, other, False, {co_ref})),
        verify_with='wrong_key_not_in_cnf', known_references=[co_ref])
    add('checkout-receipt-unknown-reference', 'checkout_receipt',
        'Signature valid but reference is not among the known closed mandates.',
        c_rcpt_jwt, False, res(sdk_receipt(c_rcpt_jwt, merchant_k, False, set())),
        verify_with='merchant', known_references=[])
    bad_c = dict(c_rcpt, reference=compute_sha256_b64url('another mandate'))
    bad_c_jwt = create_jwt(hdr('merchant-key-1'), bad_c, merchant_k)
    add('checkout-receipt-mismatched-reference', 'checkout_receipt',
        'Validly signed receipt whose reference points at a different closed mandate.',
        bad_c_jwt, False, res(sdk_receipt(bad_c_jwt, merchant_k, False, {co_ref})),
        verify_with='merchant', known_references=[co_ref])
    add('payment-receipt-valid', 'payment_receipt',
        'PSP-signed ES256 receipt; reference = base64url(sha256(closed payment mandate JWT)).',
        p_rcpt_jwt, True, res(sdk_receipt(p_rcpt_jwt, psp_k, True, {pay_ref})),
        verify_with='payment_service_provider', known_references=[pay_ref], payload=p_rcpt)
    add('payment-receipt-wrong-key', 'payment_receipt', 'Verified against the wrong key.',
        p_rcpt_jwt, False, res(sdk_receipt(p_rcpt_jwt, other, True, {pay_ref})),
        verify_with='wrong_key_not_in_cnf', known_references=[pay_ref])
    bad_p = dict(p_rcpt, reference=compute_sha256_b64url('another payment mandate'))
    bad_p_jwt = create_jwt(hdr('psp-key-1'), bad_p, psp_k)
    add('payment-receipt-mismatched-reference', 'payment_receipt',
        'Validly signed receipt whose reference points at a different closed mandate.',
        bad_p_jwt, False, res(sdk_receipt(bad_p_jwt, psp_k, True, {pay_ref})),
        verify_with='payment_service_provider', known_references=[pay_ref])
    tp_h, tp_p, tp_s = p_rcpt_jwt.split('.')
    pp_d = json.loads(b64url_decode(tp_p))
    pp_d['status'] = 'Error'
    tamp = '.'.join([tp_h, b64url_encode(json.dumps(pp_d).encode()), tp_s])
    add('payment-receipt-tampered-payload', 'payment_receipt',
        'Payload edited after signing.', tamp, False,
        res(sdk_receipt(tamp, psp_k, True, {pay_ref})),
        verify_with='payment_service_provider', known_references=[pay_ref])

    out = {
        'format': 'ap2-interop-vectors/1',
        'ap2_sdk': {'repo': 'https://github.com/google-agentic-commerce/AP2',
                    'commit': sdk_commit, 'release': '0.2.0'},
        'generated_at_unix': now,
        'note': ('Throwaway test keys only; private keys are not exported. '
                 'expected_valid is the verdict a conforming implementation should reach; '
                 'sdk_result is what the reference Python SDK returned when the vectors were made.'),
        'jwks': {'keys': keys},
        'vectors': vectors,
    }
    args.out.write_text(json.dumps(out, indent=2) + '\n')
    n_dis = sum(1 for v in vectors if v.get('sdk_disagrees_with_expected'))
    print(f'wrote {len(vectors)} vectors to {args.out}; SDK disagrees with expected on {n_dis}')


if __name__ == '__main__':
    main()
