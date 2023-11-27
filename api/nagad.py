import base64
import random
import string
import pytz
from datetime import datetime

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from kombu.utils import json
from decouple import config


def generate_challenge(string_length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(string_length))


def get_timestamp():
    tz = pytz.timezone('Asia/Dhaka')
    now = datetime.now(tz)
    return now.strftime('%Y%m%d%H%M%S')


def encrypt_data_using_public_key(data: str, pg_public_key: str):
    pk = "-----BEGIN PUBLIC KEY-----\n" + \
        pg_public_key + "\n-----END PUBLIC KEY-----"

    try:
        public_key = serialization.load_pem_public_key(
            pk.encode(), backend=default_backend())
        encrypted_data = public_key.encrypt(data.encode(), padding.PKCS1v15())
        data = base64.b64encode(encrypted_data)
        return data.decode('utf-8'), None
    except Exception as e:
        # LOGGER.error(e)
        print(e)
        return None, e


def decrypt_data_using_private_key(data: str, merchant_private_key: str):
    pk = "-----BEGIN RSA PRIVATE KEY-----\n" + \
        merchant_private_key + "\n-----END RSA PRIVATE KEY-----"

    try:
        private_key = serialization.load_pem_private_key(
            pk.encode(), password=None, backend=default_backend())
        original_message = private_key.decrypt(data, padding.PKCS1v15())
        return original_message.decode('utf-8'), None
    except Exception as e:
        # LOGGER.error(e)
        print(e)
        return None, e


def generate_signature(data: str, merchant_private_key: str):
    pk = "-----BEGIN RSA PRIVATE KEY-----\n" + \
        merchant_private_key + "\n-----END RSA PRIVATE KEY-----"

    try:
        private_key = serialization.load_pem_private_key(
            pk.encode(), password=None, backend=default_backend())
        sign = private_key.sign(
            data.encode(), padding.PKCS1v15(), hashes.SHA256())
        signature = base64.b64encode(sign)
        return signature.decode('utf-8'), None
    except Exception as e:
        # LOGGER.error(e)
        print(e)
        return None, e


def initiate_payment(merchant_id, invoice_number, pg_public_key, merchant_private_key, base_url):
    now = get_timestamp()

    sensitive_data = {
        'merchantId': merchant_id,
        'datetime': now,
        'orderId': invoice_number,
        'challenge': generate_challenge(20)
    }

    sensitive_data_str = json.dumps(sensitive_data)
    encrypted_sensitive_data, err = encrypt_data_using_public_key(
        sensitive_data_str, pg_public_key)

    if err is not None:
        # LOGGER.error(err)
        print(err)
        return None, err

    signature, err = generate_signature(
        sensitive_data_str, merchant_private_key)

    if err is not None:
        # LOGGER.error(err)
        print(err)
        return None, err

    data = {
        'dateTime': now,
        'sensitiveData': encrypted_sensitive_data,
        'signature': signature
    }

    headers = {
        'Content-Type': 'application/json',
        'X-KM-IP-V4': config('NAGAD_HOST_IP'),
        'X-KM-Client-Type': 'PC_WEB',
        'X-KM-Api-Version': 'v-0.2.0'
    }

    # url = "{}/remote-payment-gateway-1.0/api/dfs/check-out/initialize/{}/{}".format(base_url, merchant_id, invoice_number)

    url = f'{base_url}/api/dfs/check-out/initialize/{merchant_id}/{invoice_number}'

    try:
        response = requests.post(url, json.dumps(
            data), headers=headers, verify=False)
        json_response = response.json()

        if response.status_code != 200:
            # LOGGER.error(json_response)
            print(json_response)
            return None, json_response

        return json_response, None
    except Exception as e:
        # LOGGER.error(e)
        print(e)
        return None, e


def complete_payment(merchant_id, invoice_number, amount, challenge, pg_public_key, merchant_private_key, base_url,
                     payment_reference_id, merchant_callback_url):
    sensitive_data = {
        'merchantId': merchant_id,
        'orderId': invoice_number,
        'currencyCode': '050',
        'amount': amount,
        'challenge': challenge
    }

    sensitive_data_str = json.dumps(sensitive_data)
    encrypt_sensitive_data, err = encrypt_data_using_public_key(
        sensitive_data_str, pg_public_key)

    if err is not None:
        # LOGGER.error(err)
        print(err)
        return None, err

    signature, err = generate_signature(
        sensitive_data_str, merchant_private_key)

    if err is not None:
        # LOGGER.error(err)
        print(err)
        return None, err

    data = {
        'dateTime': get_timestamp(),
        'sensitiveData': encrypt_sensitive_data,
        'signature': signature,
        'merchantCallbackURL': merchant_callback_url,
        'additionalMerchantInfo':  {
            "productName": "shirt",
            "productCount": 1
        }

    }

    headers = {
        'Content-Type': 'application/json',
        'X-KM-IP-V4': config('NAGAD_HOST_IP'),
        'X-KM-Client-Type': 'PC_WEB',
        'X-KM-Api-Version': 'v-0.2.0'
    }

    # url = "{}/remote-payment-gateway-1.0/api/dfs/check-out/complete/{}".format(
    #     base_url, payment_reference_id)
    url = f'{base_url}/api/dfs/check-out/complete/{payment_reference_id}'

    try:
        response = requests.post(url, data=json.dumps(
            data), headers=headers, verify=False)
        json_response = response.json()

        if response.status_code != 200:
            # LOGGER.error(json_response)
            print(json_response)
            return None, json_response

        return json_response, None
    except Exception as e:
        # LOGGER.error(e)
        print(e)
        return None, e


def get_payment_information(merchant_id, invoice_number, amount, pg_public_key, merchant_private_key, base_url, merchant_callback_url):
    initiated_data, err = initiate_payment(
        merchant_id, invoice_number, pg_public_key, merchant_private_key, base_url)

    if err is not None:
        # LOGGER.error(err)
        print(err)
        return None, err

    sensitive_data = initiated_data.get('sensitiveData')

    if sensitive_data is None:
        return None, 'Sensitive data is missing.'

    decrypted_sensitive_data, err = decrypt_data_using_private_key(base64.b64decode(sensitive_data),
                                                                   merchant_private_key)

    if err is not None:
        # LOGGER.error(err)
        print(err)
        return None, err

    decrypted_sensitive_data_dict = json.loads(decrypted_sensitive_data)

    payment_reference_id = decrypted_sensitive_data_dict.get(
        'paymentReferenceId')
    challenge = decrypted_sensitive_data_dict.get('challenge')

    if payment_reference_id is None or challenge is None:
        # LOGGER.error('Nagad payment reference or challenge is empty.')
        print('Nagad payment reference or challenge is empty.')
        return None, 'Payment reference or challenge is empty.'

    result, err = complete_payment(merchant_id, invoice_number, amount, challenge, pg_public_key, merchant_private_key,
                                   base_url, payment_reference_id, merchant_callback_url)

    if err is not None:
        # LOGGER.error(err)
        print(err)
        return None, err

    status = result.get('status')

    if status is None:
        # LOGGER.error("Nagad status not found")
        return None, "Status not found"

    if status != 'Success':
        return None, "URL not found"

    info = {
        'url': result.get('callBackUrl'),
        'payment_reference_id': payment_reference_id
    }

    return info, None


def verify_payment(base_url, payment_reference_id):
    # url = base_url + '/remote-payment-gateway-1.0/api/dfs/verify/payment/' + \
    #     payment_reference_id

    url = f'{base_url}/api/dfs/verify/payment/{payment_reference_id}'

    try:
        response = requests.get(url, verify=False)
        json_response = response.json()

        if response.status_code != 200:
            # LOGGER.error(json_response)
            print(json_response)
            return False, json_response

        status = json_response.get('status')

        if status != 'Success':
            # LOGGER.error(json_response)
            print(json_response)
            return False, json_response

        return True, json_response
    except Exception as e:
        # LOGGER.error(e)
        print(e)
        return False, {'error': e}
